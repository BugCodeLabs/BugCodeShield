package project

import (
	"net/http"
	"strings"
	"time"

	"bugcode-shield/internal/auth"
	"bugcode-shield/internal/httputil"
	"bugcode-shield/internal/org"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Project struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Service struct {
	pool *pgxpool.Pool
	orgs *org.Service
}

func New(pool *pgxpool.Pool, orgs *org.Service) *Service {
	return &Service{pool: pool, orgs: orgs}
}

type createRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Service) List(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	orgID := chi.URLParam(r, "orgID")
	if _, err := s.orgs.RequireOrgAccess(r.Context(), userID, orgID, false); err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	rows, err := s.pool.Query(r.Context(), `
		SELECT id::text, organization_id::text, name, description, created_by::text, created_at, updated_at
		FROM projects WHERE organization_id=$1 ORDER BY updated_at DESC
	`, orgID)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	defer rows.Close()
	items := make([]Project, 0)
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.OrganizationID, &p.Name, &p.Description, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
			return
		}
		items = append(items, p)
	}
	httputil.JSON(w, http.StatusOK, map[string]any{"projects": items})
}

func (s *Service) ListMine(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	rows, err := s.pool.Query(r.Context(), `
		SELECT p.id::text, p.organization_id::text, p.name, p.description, p.created_by::text, p.created_at, p.updated_at
		FROM projects p
		JOIN organization_members m ON m.organization_id = p.organization_id
		WHERE m.user_id=$1
		ORDER BY p.updated_at DESC
	`, userID)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	defer rows.Close()
	items := make([]Project, 0)
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.OrganizationID, &p.Name, &p.Description, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
			return
		}
		items = append(items, p)
	}
	httputil.JSON(w, http.StatusOK, map[string]any{"projects": items})
}

func (s *Service) Create(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	orgID := chi.URLParam(r, "orgID")
	if _, err := s.orgs.RequireOrgAccess(r.Context(), userID, orgID, true); err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	var req createRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", "Invalid JSON body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		httputil.Error(w, http.StatusBadRequest, "validation", "Project name is required")
		return
	}
	var p Project
	err := s.pool.QueryRow(r.Context(), `
		INSERT INTO projects (organization_id, name, description, created_by)
		VALUES ($1,$2,$3,$4)
		RETURNING id::text, organization_id::text, name, description, created_by::text, created_at, updated_at
	`, orgID, name, strings.TrimSpace(req.Description), userID).Scan(
		&p.ID, &p.OrganizationID, &p.Name, &p.Description, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	httputil.JSON(w, http.StatusCreated, p)
}

func (s *Service) Get(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	projectID := chi.URLParam(r, "projectID")
	if _, err := s.orgs.RequireProjectAccess(r.Context(), userID, projectID, false); err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	var p Project
	err := s.pool.QueryRow(r.Context(), `
		SELECT id::text, organization_id::text, name, description, created_by::text, created_at, updated_at
		FROM projects WHERE id=$1
	`, projectID).Scan(&p.ID, &p.OrganizationID, &p.Name, &p.Description, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteAppError(w, httputil.ErrNotFound)
			return
		}
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	httputil.JSON(w, http.StatusOK, p)
}
