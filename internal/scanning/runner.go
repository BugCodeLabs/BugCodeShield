package scanning

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type RunResult struct {
	Scanner  string
	Output   []byte
	Log      string
	Err      error
	ExitCode int
}

type Runner struct {
	HostWorkspace string
	HostCache     string
	ContainerSrc  string
	Network       string
	Timeout       time.Duration
	SonarURL      string
	SonarPassword string

	sonarMu    sync.Mutex
	sonarToken string
}

func (r *Runner) Run(ctx context.Context, scanner, scanID, hostSrc, hostOut, localOut string) RunResult {
	if r.Timeout == 0 {
		r.Timeout = 15 * time.Minute
	}
	if localOut == "" {
		localOut = hostOut
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	_ = os.MkdirAll(localOut, 0o777)
	_ = os.Chmod(localOut, 0o777)

	if scanner == "gitleaks" {
		_ = os.WriteFile(filepath.Join(localOut, "gitleaks.toml"), []byte(gitleaksConfig), 0o644)
	}

	image, args := commandFor(scanner, scanID)
	if image == "" {
		return RunResult{Scanner: scanner, Err: fmt.Errorf("unsupported scanner %s", scanner)}
	}
	shortID := scanID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	name := fmt.Sprintf("bugcodeshield-%s-%s", scanner, shortID)
	ensureImage(ctx, image)

	memory, pids := "1536m", "256"
	if scanner == "sonarqube" {
		memory, pids = "2g", "512"
	}

	dockerArgs := []string{
		"run", "--rm",
		"--name", name,
		"--memory", memory,
		"--cpus", "1",
		"--pids-limit", pids,
		"--tmpfs", "/tmp:rw,exec,nosuid,size=2g",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"-v", hostSrc + ":/src:ro",
		"-v", hostOut + ":/out",
	}
	if scanner == "trivy" && r.HostCache != "" {
		dockerArgs = append(dockerArgs,
			"-e", "TRIVY_CACHE_DIR=/cache",
			"-v", r.HostCache+":/cache",
		)
	} else {
		dockerArgs = append(dockerArgs, "-e", "TRIVY_CACHE_DIR=/tmp/trivy")
	}
	if scanner == "sonarqube" {
		token, err := r.ensureSonarToken(ctx)
		if err != nil {
			return RunResult{Scanner: scanner, Err: err}
		}
		dockerArgs = append(dockerArgs,
			"--user", "0:0",
			"-e", "SONAR_HOST_URL="+strings.TrimRight(r.SonarURL, "/"),
			"-e", "SONAR_TOKEN="+token,
			"-e", "SONAR_USER_HOME=/tmp/.sonar",
		)
	}
	network := r.Network
	if scanner == "sonarqube" && network == "" {
		network = "bugcode-shield_scanners"
	}
	if network != "" {
		dockerArgs = append(dockerArgs, "--network", network)
	}
	dockerArgs = append(dockerArgs, image)
	dockerArgs = append(dockerArgs, args...)

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	combined, err := cmd.CombinedOutput()
	res := RunResult{Scanner: scanner, Err: err, Log: sanitizeScannerLog(string(combined))}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if scanner == "sonarqube" {
		report, collectErr := r.collectSonarQube(ctx, scanID, localOut)
		if len(report) > 0 {
			res.Output = report
			_ = os.WriteFile(filepath.Join(localOut, "sonarqube.json"), report, 0o644)
			res.Err = nil
		} else if collectErr != nil {
			res.Err = fmt.Errorf("%s failed: %w", scanner, collectErr)
		}
	} else {
		outFile := outputFile(localOut, scanner)
		if data, readErr := os.ReadFile(outFile); readErr == nil && len(bytes.TrimSpace(data)) > 0 {
			res.Output = data
		} else if extracted := extractJSON(combined); len(extracted) > 0 {
			res.Output = extracted
		}
	}
	// Gitleaks (and some other scanners) exit 1 when they found issues.
	if res.ExitCode == 1 && len(res.Output) > 0 {
		res.Err = nil
	}
	if res.Err != nil && len(res.Output) == 0 && err != nil {
		res.Err = fmt.Errorf("%s failed: %w: %s", scanner, err, truncate(string(combined), 500))
	}
	return res
}

func ensureImage(ctx context.Context, image string) {
	if image == "" {
		return
	}
	if exec.CommandContext(ctx, "docker", "image", "inspect", image).Run() == nil {
		return
	}
	_ = exec.CommandContext(ctx, "docker", "pull", image).Run()
}

func commandFor(scanner, scanID string) (image string, args []string) {
	switch scanner {
	case "semgrep":
		return "semgrep/semgrep:1.97.0", []string{
			"semgrep", "scan",
			"--metrics", "off",
			"--disable-version-check",
			"--config", "p/default",
			"--config", "p/security-audit",
			"--config", "p/secrets",
			"--config", "p/owasp-top-ten",
			"--config", "p/javascript",
			"--config", "p/typescript",
			"--config", "p/python",
			"--config", "p/golang",
			"--config", "p/java",
			"--config", "p/php",
			"--config", "p/nodejs",
			"--exclude", "node_modules",
			"--exclude", ".git",
			"--exclude", "dist",
			"--exclude", "build",
			"--exclude", "vendor",
			"--exclude", ".next",
			"--exclude", "coverage",
			"--exclude", "target",
			"--json",
			"--output", "/out/semgrep.json",
			"/src",
		}
	case "trivy":
		return "aquasec/trivy:0.58.1", []string{
			"fs",
			"--scanners", "vuln,misconfig,secret",
			"--skip-dirs", "node_modules",
			"--skip-dirs", ".git",
			"--skip-dirs", "dist",
			"--skip-dirs", "build",
			"--skip-dirs", "vendor",
			"--skip-dirs", ".next",
			"--quiet",
			"--format", "json",
			"--output", "/out/trivy.json",
			"/src",
		}
	case "gitleaks":
		return "zricethezav/gitleaks:v8.21.2", []string{
			"detect",
			"--source", "/src",
			"--no-git",
			"--config", "/out/gitleaks.toml",
			"--report-format", "json",
			"--report-path", "/out/gitleaks.json",
		}
	case "dependency-check":
		return "owasp/dependency-check:12.1.0", []string{"--scan", "/src", "--format", "JSON", "--out", "/out", "--noupdate", "--exclude", "**/node_modules/**", "--exclude", "**/.git/**"}
	case "sonarqube":
		key := sonarProjectKey(scanID)
		return sonarScannerImage, []string{
			"-Dsonar.projectKey=" + key,
			"-Dsonar.projectName=" + key,
			"-Dsonar.projectBaseDir=/src",
			"-Dsonar.sources=.",
			"-Dsonar.working.directory=/tmp/.scannerwork",
			"-Dsonar.scm.disabled=true",
			"-Dsonar.qualitygate.wait=false",
			"-Dsonar.scanner.metadataFilePath=/out/report-task.txt",
			"-Dsonar.exclusions=**/node_modules/**,**/.git/**,**/dist/**,**/build/**,**/vendor/**,**/.next/**,**/coverage/**,**/target/**,**/__pycache__/**,**/venv/**,**/.venv/**",
		}
	default:
		return "", nil
	}
}

const gitleaksConfig = `title = "BugCode Shield"

[extend]
useDefault = true

[allowlist]
paths = [
  '''(^|/)node_modules/''',
  '''(^|/)\.git/''',
  '''(^|/)vendor/''',
  '''(^|/)dist/''',
  '''(^|/)build/''',
  '''(^|/)\.next/''',
  '''(^|/)coverage/''',
  '''(^|/)target/''',
  '''(^|/)__pycache__/''',
  '''(^|/)venv/''',
  '''(^|/)\.venv/''',
]
`

func outputFile(outDir, scanner string) string {
	switch scanner {
	case "semgrep":
		return filepath.Join(outDir, "semgrep.json")
	case "trivy":
		return filepath.Join(outDir, "trivy.json")
	case "gitleaks":
		return filepath.Join(outDir, "gitleaks.json")
	case "dependency-check":
		matches, _ := filepath.Glob(filepath.Join(outDir, "*.json"))
		if len(matches) > 0 {
			return matches[0]
		}
		return filepath.Join(outDir, "dependency-check-report.json")
	case "sonarqube":
		return filepath.Join(outDir, "sonarqube.json")
	default:
		return filepath.Join(outDir, scanner+".json")
	}
}

func extractJSON(raw []byte) []byte {
	s := bytes.TrimSpace(raw)
	start := bytes.IndexAny(s, "{[")
	if start < 0 {
		return nil
	}
	s = s[start:]
	end := bytes.LastIndexAny(s, "}]")
	if end < 0 {
		return nil
	}
	candidate := bytes.TrimSpace(s[:end+1])
	if len(candidate) == 0 || (candidate[0] != '{' && candidate[0] != '[') {
		return nil
	}
	return candidate
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
}

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func sanitizeScannerLog(s string) string {
	s = ansiEscape.ReplaceAllString(s, "")
	var kept []string
	for _, line := range strings.Split(s, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "secret:") || strings.Contains(lower, "x-access-token:") {
			continue
		}
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		kept = append(kept, line)
		if len(kept) > 40 {
			break
		}
	}
	return truncate(strings.Join(kept, "\n"), 1500)
}
