package worker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"bugcode-shield/internal/crypto"
	"bugcode-shield/internal/finding"
	"bugcode-shield/internal/live"
	"bugcode-shield/internal/queue"
	"bugcode-shield/internal/scan"
	"bugcode-shield/internal/scanning"
	"bugcode-shield/internal/source"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
)

type Config struct {
	Workspace     string
	HostWorkspace string
	HostCache     string
	Network       string
	EncKey        []byte
	Bucket        string
	SonarURL      string
	SonarPassword string
}

type Worker struct {
	pool     *pgxpool.Pool
	minio    *minio.Client
	scans    *scan.Service
	findings *finding.Service
	events   *live.Hub
	cfg      Config
	logger   *slog.Logger
	runner   scanning.Runner
}

func New(pool *pgxpool.Pool, mc *minio.Client, scans *scan.Service, findings *finding.Service, events *live.Hub, cfg Config, logger *slog.Logger) *Worker {
	return &Worker{
		pool:     pool,
		minio:    mc,
		scans:    scans,
		findings: findings,
		events:   events,
		cfg:      cfg,
		logger:   logger,
		runner: scanning.Runner{
			HostWorkspace: cfg.HostWorkspace,
			HostCache:     cfg.HostCache,
			Network:       cfg.Network,
			Timeout:       15 * time.Minute,
			SonarURL:      cfg.SonarURL,
			SonarPassword: cfg.SonarPassword,
		},
	}
}

func (w *Worker) Handle(ctx context.Context, job queue.ScanJob) error {
	w.logger.Info("scan job received", "scan_id", job.ScanID)
	var status string
	if err := w.pool.QueryRow(ctx, `SELECT status FROM scans WHERE id=$1`, job.ScanID).Scan(&status); err != nil {
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	}
	if status == "CANCELLED" {
		return nil
	}

	_ = w.scans.UpdateStatus(ctx, job.ScanID, "PREPARING", nil)
	w.log(ctx, job.ScanID, "", "info", "Preparing source")

	workDir := filepath.Join(w.cfg.Workspace, job.ScanID)
	srcDir := filepath.Join(workDir, "src")
	outDir := filepath.Join(workDir, "out")
	_ = os.RemoveAll(workDir)
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		return w.fail(ctx, job.ScanID, err)
	}
	if err := os.MkdirAll(outDir, 0o777); err != nil {
		return w.fail(ctx, job.ScanID, err)
	}
	_ = os.Chmod(workDir, 0o755)
	_ = os.Chmod(outDir, 0o777)
	defer os.RemoveAll(workDir)

	projectID, scanners, hostSrc, copied, sourceDesc, err := w.materializeSource(ctx, job.ScanID, srcDir)
	if err != nil {
		return w.fail(ctx, job.ScanID, err)
	}
	w.log(ctx, job.ScanID, "", "info", "Source ready: "+sourceDesc)
	if copied {
		_ = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				_ = os.Chmod(path, 0o755)
			} else {
				_ = os.Chmod(path, 0o644)
			}
			return nil
		})
	}

	if cancelled(ctx, w.pool, job.ScanID) {
		return nil
	}
	_ = w.scans.UpdateStatus(ctx, job.ScanID, "RUNNING", nil)
	w.log(ctx, job.ScanID, "", "info", "Running "+strings.Join(scanners, ", ")+". Large folders can take several minutes.")

	if hostSrc == "" {
		hostSrc = filepath.Join(w.cfg.HostWorkspace, job.ScanID, "src")
	}
	hostOut := filepath.Join(w.cfg.HostWorkspace, job.ScanID, "out")

	total := 0
	for _, scanner := range scanners {
		if cancelled(ctx, w.pool, job.ScanID) {
			return nil
		}
		w.log(ctx, job.ScanID, scanner, "info", "Starting scanner")
		if scanner == "sonarqube" {
			w.log(ctx, job.ScanID, scanner, "info", "Waiting for local SonarQube, then running sonar-scanner. First start can take a few minutes.")
		}
		res := w.runner.Run(ctx, scanner, job.ScanID, hostSrc, hostOut, outDir)
		if res.Log != "" {
			w.log(ctx, job.ScanID, scanner, "info", res.Log)
		}
		if len(res.Output) == 0 && res.Err != nil {
			w.log(ctx, job.ScanID, scanner, "error", "Scanner failed: "+safeErr(res.Err))
			continue
		}
		if res.Err != nil {
			w.log(ctx, job.ScanID, scanner, "info", "Scanner reported issues; ingesting available findings")
		}
		parsed := parse(scanner, job.ScanID, projectID, res.Output)
		if err := w.findings.InsertAll(ctx, parsed); err != nil {
			return w.fail(ctx, job.ScanID, err)
		}
		total += len(parsed)
		w.log(ctx, job.ScanID, scanner, "info", fmt.Sprintf("Collected %d findings", len(parsed)))
	}
	_ = w.scans.UpdateStatus(ctx, job.ScanID, "COMPLETED", nil)
	w.log(ctx, job.ScanID, "", "info", fmt.Sprintf("Scan completed with %d findings", total))
	return nil
}

func parse(scanner, scanID, projectID string, raw []byte) []finding.Finding {
	switch scanner {
	case "semgrep":
		return scanning.ParseSemgrep(scanID, projectID, raw)
	case "trivy":
		return scanning.ParseTrivy(scanID, projectID, raw)
	case "gitleaks":
		return scanning.ParseGitleaks(scanID, projectID, raw)
	case "dependency-check":
		return scanning.ParseDependencyCheck(scanID, projectID, raw)
	case "sonarqube":
		return scanning.ParseSonarQube(scanID, projectID, raw)
	default:
		return nil
	}
}

func (w *Worker) materializeSource(ctx context.Context, scanID, srcDir string) (projectID string, scanners []string, hostSrc string, copied bool, desc string, err error) {
	var sourceID, kind string
	var storageKey, githubRepo, githubRef, localPath *string
	var token []byte
	err = w.pool.QueryRow(ctx, `
		SELECT s.project_id::text, s.scanners, src.id::text, src.kind, src.storage_key, src.github_repo, src.github_ref, src.local_path, src.token_ciphertext
		FROM scans s
		JOIN project_sources src ON src.id = s.source_id
		WHERE s.id=$1
	`, scanID).Scan(&projectID, &scanners, &sourceID, &kind, &storageKey, &githubRepo, &githubRef, &localPath, &token)
	if err != nil {
		return "", nil, "", false, "", err
	}
	if localPath != nil && strings.TrimSpace(*localPath) != "" && (kind == "local" || kind == "zip") {
		desc = "folder " + *localPath + " (scanned in place on this computer)"
		w.log(ctx, scanID, "", "info", "Scanning in place from "+*localPath)
		return projectID, scanners, *localPath, false, desc, nil
	}
	switch kind {
	case "zip", "files":
		if storageKey == nil {
			return "", nil, "", false, "", fmt.Errorf("source archive missing")
		}
		obj, err := w.minio.GetObject(ctx, w.cfg.Bucket, *storageKey, minio.GetObjectOptions{})
		if err != nil {
			return "", nil, "", false, "", err
		}
		defer obj.Close()
		raw, err := io.ReadAll(obj)
		if err != nil {
			return "", nil, "", false, "", err
		}
		if _, err := source.SafeExtractZip(bytes.NewReader(raw), int64(len(raw)), srcDir); err != nil {
			return "", nil, "", false, "", err
		}
		count, _, _ := source.CountScanFiles(srcDir)
		return projectID, scanners, "", true, fmt.Sprintf("extracted archive (%d files)", count), nil
	case "github":
		if githubRepo == nil {
			return "", nil, "", false, "", fmt.Errorf("github repository missing")
		}
		ref := "main"
		if githubRef != nil && *githubRef != "" {
			ref = *githubRef
		}
		repo := source.NormalizeGitHubRepo(*githubRepo)
		url := "https://github.com/" + repo + ".git"
		if len(token) > 0 {
			plain, decErr := crypto.Decrypt(w.cfg.EncKey, token)
			if decErr != nil {
				return "", nil, "", false, "", fmt.Errorf("github token decrypt failed")
			}
			url = "https://x-access-token:" + string(plain) + "@github.com/" + repo + ".git"
		}
		w.log(ctx, scanID, "", "info", "Cloning github.com/"+repo+"@"+ref+" into an isolated scan workspace")
		cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--branch", ref, url, srcDir)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		out, cloneErr := cmd.CombinedOutput()
		if cloneErr != nil {
			w.logger.Error("github clone failed", "scan_id", scanID)
			_ = out
			return "", nil, "", false, "", fmt.Errorf("github clone failed")
		}
		shaCmd := exec.CommandContext(ctx, "git", "-C", srcDir, "rev-parse", "HEAD")
		sha, _ := shaCmd.Output()
		commit := strings.TrimSpace(string(sha))
		if commit != "" {
			_, _ = w.pool.Exec(ctx, `UPDATE project_sources SET commit_sha=$2 WHERE id=$1`, sourceID, commit)
		}
		count, _, _ := source.CountScanFiles(srcDir)
		w.log(ctx, scanID, "", "info", fmt.Sprintf("Cloned %d files from github.com/%s", count, repo))
		return projectID, scanners, "", true, fmt.Sprintf("github.com/%s@%s (%d files)", repo, ref, count), nil
	default:
		return "", nil, "", false, "", fmt.Errorf("unknown source kind")
	}
}

func (w *Worker) fail(ctx context.Context, scanID string, err error) error {
	msg := safeErr(err)
	_ = w.scans.UpdateStatus(ctx, scanID, "FAILED", &msg)
	w.log(ctx, scanID, "", "error", msg)
	return nil
}

func (w *Worker) log(ctx context.Context, scanID, scanner, level, message string) {
	var scannerArg any
	if scanner == "" {
		scannerArg = nil
	} else {
		scannerArg = scanner
	}
	_, _ = w.pool.Exec(ctx, `INSERT INTO scan_logs (scan_id, scanner, level, message) VALUES ($1,$2,$3,$4)`, scanID, scannerArg, level, message)
	if w.events != nil {
		w.events.Publish(ctx, live.Event{Type: "log", ScanID: scanID})
	}
}

func (w *Worker) Logs(ctx context.Context, scanID string) ([]map[string]any, error) {
	rows, err := w.pool.Query(ctx, `SELECT scanner, level, message, created_at FROM scan_logs WHERE scan_id=$1 ORDER BY id ASC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var scanner *string
		var level, message string
		var created time.Time
		if err := rows.Scan(&scanner, &level, &message, &created); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{
			"scanner":    scanner,
			"level":      level,
			"message":    message,
			"created_at": created,
		})
	}
	return items, nil
}

func cancelled(ctx context.Context, pool *pgxpool.Pool, scanID string) bool {
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM scans WHERE id=$1`, scanID).Scan(&status); err != nil {
		return false
	}
	return status == "CANCELLED"
}

func safeErr(err error) string {
	if err == nil {
		return "unknown error"
	}
	msg := err.Error()
	msg = strings.ReplaceAll(msg, "x-access-token:", "x-access-token:[redacted]")
	if len(msg) > 400 {
		return msg[:400]
	}
	return msg
}
