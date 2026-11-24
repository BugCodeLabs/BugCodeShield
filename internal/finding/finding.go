package finding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"bugcode-shield/internal/auth"
	"bugcode-shield/internal/httputil"
	"bugcode-shield/internal/org"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Finding struct {
	ID           string          `json:"id"`
	ScanID       string          `json:"scan_id"`
	ProjectID    string          `json:"project_id"`
	Scanner      string          `json:"scanner"`
	RuleID       string          `json:"rule_id"`
	Title        string          `json:"title"`
	Description  string          `json:"description"`
	Severity     string          `json:"severity"`
	CWE          *string         `json:"cwe,omitempty"`
	CVE          *string         `json:"cve,omitempty"`
	FilePath     *string         `json:"file_path,omitempty"`
	StartLine    *int            `json:"start_line,omitempty"`
	EndLine      *int            `json:"end_line,omitempty"`
	Snippet      *string         `json:"snippet,omitempty"`
	Remediation  *string         `json:"remediation,omitempty"`
	Fingerprint  string          `json:"fingerprint"`
	DetectedAt   time.Time       `json:"detected_at"`
	Raw          json.RawMessage `json:"-"`
}

type Service struct {
	pool *pgxpool.Pool
	orgs *org.Service
}

func New(pool *pgxpool.Pool, orgs *org.Service) *Service {
	return &Service{pool: pool, orgs: orgs}
}

func Fingerprint(scanner, rule, path string, line int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d", scanner, rule, path, line)))
	return hex.EncodeToString(h[:])
}

func (s *Service) InsertAll(ctx context.Context, items []Finding) error {
	for _, item := range items {
		if len(item.Raw) == 0 {
			item.Raw = json.RawMessage(`{}`)
		}
		if item.Fingerprint == "" {
			line := 0
			if item.StartLine != nil {
				line = *item.StartLine
			}
			path := ""
			if item.FilePath != nil {
				path = *item.FilePath
			}
			item.Fingerprint = Fingerprint(item.Scanner, item.RuleID, path, line)
		}
		_, err := s.pool.Exec(ctx, `
			INSERT INTO findings (
				scan_id, project_id, scanner, rule_id, title, description, severity, cwe, cve,
				file_path, start_line, end_line, snippet, remediation, fingerprint, raw
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
			ON CONFLICT (scan_id, fingerprint) DO NOTHING
		`, item.ScanID, item.ProjectID, item.Scanner, item.RuleID, item.Title, item.Description, item.Severity,
			item.CWE, item.CVE, item.FilePath, item.StartLine, item.EndLine, item.Snippet, item.Remediation, item.Fingerprint, item.Raw)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) List(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	scanID := chi.URLParam(r, "scanID")
	projectID, err := s.authorizeScan(r, userID, scanID)
	if err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	_ = projectID
	q := r.URL.Query()
	severity := strings.ToLower(strings.TrimSpace(q.Get("severity")))
	scanner := strings.ToLower(strings.TrimSpace(q.Get("scanner")))
	file := strings.TrimSpace(q.Get("file"))
	search := strings.TrimSpace(q.Get("q"))

	rows, err := s.pool.Query(r.Context(), `
		SELECT id::text, scan_id::text, project_id::text, scanner, rule_id, title, description, severity, cwe, cve,
		       file_path, start_line, end_line, snippet, remediation, fingerprint, detected_at
		FROM findings
		WHERE scan_id=$1
		  AND ($2='' OR severity=$2)
		  AND ($3='' OR scanner=$3)
		  AND ($4='' OR file_path ILIKE '%'||$4||'%')
		  AND ($5='' OR title ILIKE '%'||$5||'%' OR description ILIKE '%'||$5||'%' OR rule_id ILIKE '%'||$5||'%')
		ORDER BY
		  CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
		  file_path, start_line
	`, scanID, severity, scanner, file, search)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	defer rows.Close()
	items := make([]Finding, 0)
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.ScanID, &f.ProjectID, &f.Scanner, &f.RuleID, &f.Title, &f.Description, &f.Severity, &f.CWE, &f.CVE, &f.FilePath, &f.StartLine, &f.EndLine, &f.Snippet, &f.Remediation, &f.Fingerprint, &f.DetectedAt); err != nil {
			httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
			return
		}
		items = append(items, f)
	}
	httputil.JSON(w, http.StatusOK, map[string]any{"findings": items, "count": len(items)})
}

func (s *Service) Summary(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	projectID := chi.URLParam(r, "projectID")
	if _, err := s.orgs.RequireProjectAccess(r.Context(), userID, projectID, false); err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	var latest pgtype.Text
	_ = s.pool.QueryRow(r.Context(), `SELECT id::text FROM scans WHERE project_id=$1 AND status='COMPLETED' ORDER BY created_at DESC LIMIT 1`, projectID).Scan(&latest)
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
	if latest.Valid {
		rows, err := s.pool.Query(r.Context(), `SELECT severity, COUNT(*) FROM findings WHERE scan_id=$1 GROUP BY severity`, latest.String)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var sev string
				var n int
				if err := rows.Scan(&sev, &n); err == nil {
					counts[sev] = n
					counts["total"] += n
				}
			}
		}
	}
	httputil.JSON(w, http.StatusOK, map[string]any{
		"latest_scan_id": latest.String,
		"severity":       counts,
	})
}

func (s *Service) ExportJSON(w http.ResponseWriter, r *http.Request) {
	s.export(w, r, "json")
}

func (s *Service) ExportSARIF(w http.ResponseWriter, r *http.Request) {
	s.export(w, r, "sarif")
}

func (s *Service) export(w http.ResponseWriter, r *http.Request, format string) {
	userID := auth.UserID(r.Context())
	scanID := chi.URLParam(r, "scanID")
	if _, err := s.authorizeScan(r, userID, scanID); err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	rows, err := s.pool.Query(r.Context(), `
		SELECT id::text, scanner, rule_id, title, description, severity, cwe, cve, file_path, start_line, end_line, remediation
		FROM findings WHERE scan_id=$1
	`, scanID)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	defer rows.Close()
	type exportRow struct {
		ID, Scanner, RuleID, Title, Description, Severity string
		CWE, CVE, FilePath, Remediation                   *string
		StartLine, EndLine                                *int
	}
	items := make([]exportRow, 0)
	for rows.Next() {
		var item exportRow
		if err := rows.Scan(&item.ID, &item.Scanner, &item.RuleID, &item.Title, &item.Description, &item.Severity, &item.CWE, &item.CVE, &item.FilePath, &item.StartLine, &item.EndLine, &item.Remediation); err != nil {
			httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
			return
		}
		items = append(items, item)
	}
	if format == "sarif" {
		results := make([]map[string]any, 0, len(items))
		for _, item := range items {
			level := "note"
			switch item.Severity {
			case "critical", "high":
				level = "error"
			case "medium":
				level = "warning"
			}
			result := map[string]any{
				"ruleId":  item.RuleID,
				"level":   level,
				"message": map[string]any{"text": item.Title},
			}
			if item.FilePath != nil {
				region := map[string]any{}
				if item.StartLine != nil {
					region["startLine"] = *item.StartLine
				}
				if item.EndLine != nil {
					region["endLine"] = *item.EndLine
				}
				result["locations"] = []map[string]any{{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{"uri": *item.FilePath},
						"region":           region,
					},
				}}
			}
			results = append(results, result)
		}
		httputil.JSON(w, http.StatusOK, map[string]any{
			"version": "2.1.0",
			"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
			"runs": []map[string]any{{
				"tool":    map[string]any{"driver": map[string]any{"name": "BugCode Shield"}},
				"results": results,
			}},
		})
		return
	}
	httputil.JSON(w, http.StatusOK, map[string]any{"scan_id": scanID, "findings": items})
}

func (s *Service) authorizeScan(r *http.Request, userID, scanID string) (string, error) {
	var projectID string
	err := s.pool.QueryRow(r.Context(), `SELECT project_id::text FROM scans WHERE id=$1`, scanID).Scan(&projectID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", httputil.ErrNotFound
		}
		return "", err
	}
	if _, err := s.orgs.RequireProjectAccess(r.Context(), userID, projectID, false); err != nil {
		return "", err
	}
	return projectID, nil
}

func (s *Service) Get(ctx context.Context, userID, findingID string) (Finding, error) {
	var f Finding
	var projectID string
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, scan_id::text, project_id::text, scanner, rule_id, title, description, severity, cwe, cve,
		       file_path, start_line, end_line, snippet, remediation, fingerprint, detected_at
		FROM findings WHERE id=$1
	`, findingID).Scan(&f.ID, &f.ScanID, &f.ProjectID, &f.Scanner, &f.RuleID, &f.Title, &f.Description, &f.Severity, &f.CWE, &f.CVE, &f.FilePath, &f.StartLine, &f.EndLine, &f.Snippet, &f.Remediation, &f.Fingerprint, &f.DetectedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Finding{}, httputil.ErrNotFound
		}
		return Finding{}, err
	}
	projectID = f.ProjectID
	if _, err := s.orgs.RequireProjectAccess(ctx, userID, projectID, false); err != nil {
		return Finding{}, err
	}
	return f, nil
}
