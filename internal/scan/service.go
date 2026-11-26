package scan

import (
	"context"
	"net/http"
	"strings"
	"time"

	"bugcode-shield/internal/auth"
	"bugcode-shield/internal/httputil"
	"bugcode-shield/internal/live"
	"bugcode-shield/internal/org"
	"bugcode-shield/internal/queue"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var allowedScanners = map[string]struct{}{
	"semgrep":          {},
	"trivy":            {},
	"gitleaks":         {},
	"dependency-check": {},
	"sonarqube":        {},
}

type Scan struct {
	ID           string     `json:"id"`
	ProjectID    string     `json:"project_id"`
	SourceID     string     `json:"source_id"`
	Status       string     `json:"status"`
	Scanners     []string   `json:"scanners"`
	ErrorMessage *string    `json:"error_message,omitempty"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	FindingCount int        `json:"finding_count"`
	SourceKind   string     `json:"source_kind,omitempty"`
	SourceLabel  string     `json:"source_label,omitempty"`
	GitHubRepo   *string    `json:"github_repo,omitempty"`
	LocalPath    *string    `json:"local_path,omitempty"`
}

type Service struct {
	pool   *pgxpool.Pool
	orgs   *org.Service
	queue  *queue.Client
	events *live.Hub
	auth   *auth.Service
}

func New(pool *pgxpool.Pool, orgs *org.Service, q *queue.Client, events *live.Hub, authSvc *auth.Service) *Service {
	return &Service{pool: pool, orgs: orgs, queue: q, events: events, auth: authSvc}
}

type createRequest struct {
	SourceID string   `json:"source_id"`
	Scanners []string `json:"scanners"`
}

func (s *Service) Create(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	projectID := chi.URLParam(r, "projectID")
	if _, err := s.orgs.RequireProjectAccess(r.Context(), userID, projectID, true); err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	var req createRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", "Invalid JSON body")
		return
	}
	if strings.TrimSpace(req.SourceID) == "" {
		httputil.Error(w, http.StatusBadRequest, "validation", "source_id is required")
		return
	}
	scanners := req.Scanners
	if len(scanners) == 0 {
		scanners = []string{"semgrep", "trivy", "gitleaks"}
	}
	for _, name := range scanners {
		if _, ok := allowedScanners[name]; !ok {
			httputil.Error(w, http.StatusBadRequest, "validation", "Unsupported scanner: "+name)
			return
		}
	}
	var exists bool
	if err := s.pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM project_sources WHERE id=$1 AND project_id=$2)`, req.SourceID, projectID).Scan(&exists); err != nil || !exists {
		httputil.Error(w, http.StatusBadRequest, "validation", "Source version not found")
		return
	}
	var sc Scan
	err := s.pool.QueryRow(r.Context(), `
		INSERT INTO scans (project_id, source_id, status, scanners, created_by)
		VALUES ($1,$2,'QUEUED',$3,$4)
		RETURNING id::text, project_id::text, source_id::text, status, scanners, error_message, started_at, finished_at, created_at
	`, projectID, req.SourceID, scanners, userID).Scan(
		&sc.ID, &sc.ProjectID, &sc.SourceID, &sc.Status, &sc.Scanners, &sc.ErrorMessage, &sc.StartedAt, &sc.FinishedAt, &sc.CreatedAt,
	)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	if err := s.queue.PublishScan(r.Context(), queue.ScanJob{ScanID: sc.ID}); err != nil {
		_, _ = s.pool.Exec(r.Context(), `UPDATE scans SET status='FAILED', error_message=$2 WHERE id=$1`, sc.ID, "failed to enqueue scan")
		httputil.Error(w, http.StatusInternalServerError, "internal", "Failed to enqueue scan")
		return
	}
	httputil.JSON(w, http.StatusAccepted, sc)
}

func (s *Service) List(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	projectID := chi.URLParam(r, "projectID")
	if _, err := s.orgs.RequireProjectAccess(r.Context(), userID, projectID, false); err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	rows, err := s.pool.Query(r.Context(), `
		SELECT s.id::text, s.project_id::text, s.source_id::text, s.status, s.scanners, s.error_message, s.started_at, s.finished_at, s.created_at,
			(SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id),
			src.kind, src.version_label, src.github_repo, src.local_path
		FROM scans s
		JOIN project_sources src ON src.id = s.source_id
		WHERE s.project_id=$1 ORDER BY s.created_at DESC
	`, projectID)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	defer rows.Close()
	items := make([]Scan, 0)
	for rows.Next() {
		var sc Scan
		if err := rows.Scan(&sc.ID, &sc.ProjectID, &sc.SourceID, &sc.Status, &sc.Scanners, &sc.ErrorMessage, &sc.StartedAt, &sc.FinishedAt, &sc.CreatedAt, &sc.FindingCount, &sc.SourceKind, &sc.SourceLabel, &sc.GitHubRepo, &sc.LocalPath); err != nil {
			httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
			return
		}
		items = append(items, sc)
	}
	httputil.JSON(w, http.StatusOK, map[string]any{"scans": items})
}

func (s *Service) Get(w http.ResponseWriter, r *http.Request) {
	sc, err := s.loadAuthorized(r)
	if err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	httputil.JSON(w, http.StatusOK, sc)
}

func (s *Service) Cancel(w http.ResponseWriter, r *http.Request) {
	sc, err := s.loadAuthorized(r)
	if err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	if sc.Status == "COMPLETED" || sc.Status == "FAILED" || sc.Status == "CANCELLED" {
		httputil.Error(w, http.StatusConflict, "conflict", "Scan is already finished")
		return
	}
	_, _ = s.pool.Exec(r.Context(), `UPDATE scans SET status='CANCELLED', finished_at=now() WHERE id=$1 AND status IN ('QUEUED','PREPARING','RUNNING')`, sc.ID)
	sc.Status = "CANCELLED"
	s.notify(r.Context(), sc.ID, "scan")
	httputil.JSON(w, http.StatusOK, sc)
}

func (s *Service) loadAuthorized(r *http.Request) (Scan, error) {
	userID := auth.UserID(r.Context())
	scanID := chi.URLParam(r, "scanID")
	sc, err := s.getByID(r.Context(), scanID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Scan{}, httputil.ErrNotFound
		}
		return Scan{}, err
	}
	if _, err := s.orgs.RequireProjectAccess(r.Context(), userID, sc.ProjectID, false); err != nil {
		return Scan{}, err
	}
	return sc, nil
}

func (s *Service) Logs(w http.ResponseWriter, r *http.Request) {
	sc, err := s.loadAuthorized(r)
	if err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT scanner, level, message, created_at FROM scan_logs WHERE scan_id=$1 ORDER BY id ASC`, sc.ID)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var scanner *string
		var level, message string
		var created time.Time
		if err := rows.Scan(&scanner, &level, &message, &created); err != nil {
			httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
			return
		}
		items = append(items, map[string]any{"scanner": scanner, "level": level, "message": message, "created_at": created})
	}
	httputil.JSON(w, http.StatusOK, map[string]any{"logs": items})
}

func (s *Service) UpdateStatus(ctx context.Context, scanID, status string, errMsg *string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE scans
		SET status=$2,
		    error_message=$3,
		    started_at=CASE WHEN $2 IN ('PREPARING','RUNNING') AND started_at IS NULL THEN now() ELSE started_at END,
		    finished_at=CASE WHEN $2 IN ('COMPLETED','FAILED','CANCELLED') THEN now() ELSE finished_at END
		WHERE id=$1
	`, scanID, status, errMsg)
	if err != nil {
		return err
	}
	s.notify(ctx, scanID, "scan")
	return nil
}
