package org

import (
	"context"
	"net/http"
	"strings"
	"time"

	"bugcode-shield/internal/auth"
	"bugcode-shield/internal/httputil"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type Service struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

func (s *Service) List(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	rows, err := s.pool.Query(r.Context(), `
		SELECT o.id::text, o.name, o.slug, m.role, o.created_at
		FROM organizations o
		JOIN organization_members m ON m.organization_id = o.id
		WHERE m.user_id = $1
		ORDER BY o.created_at ASC
	`, userID)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	defer rows.Close()
	orgs := make([]Organization, 0)
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.Role, &o.CreatedAt); err != nil {
			httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
			return
		}
		orgs = append(orgs, o)
	}
	httputil.JSON(w, http.StatusOK, map[string]any{"organizations": orgs})
}

type createRequest struct {
	Name string `json:"name"`
}

func (s *Service) Create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", "Invalid JSON body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if len(name) < 2 {
		httputil.Error(w, http.StatusBadRequest, "validation", "Organization name is required")
		return
	}
	userID := auth.UserID(r.Context())
	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	defer tx.Rollback(ctx)
	slug := strings.ToLower(strings.ReplaceAll(name, " ", "-")) + "-" + userID[:8]
	var o Organization
	if err := tx.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2)
		RETURNING id::text, name, slug, created_at
	`, name, slug).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	if _, err := tx.Exec(ctx, `INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1,$2,'owner')`, o.ID, userID); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	o.Role = "owner"
	httputil.JSON(w, http.StatusCreated, o)
}

func (s *Service) RequireProjectAccess(ctx context.Context, userID, projectID string, write bool) (orgID string, err error) {
	var role string
	err = s.pool.QueryRow(ctx, `
		SELECT p.organization_id::text, m.role
		FROM projects p
		JOIN organization_members m ON m.organization_id = p.organization_id
		WHERE p.id = $1 AND m.user_id = $2
	`, projectID, userID).Scan(&orgID, &role)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", httputil.ErrNotFound
		}
		return "", err
	}
	if write && role == "viewer" {
		return "", httputil.ErrForbidden
	}
	return orgID, nil
}

func (s *Service) RequireOrgAccess(ctx context.Context, userID, orgID string, write bool) (string, error) {
	var role string
	err := s.pool.QueryRow(ctx, `
		SELECT role FROM organization_members WHERE organization_id=$1 AND user_id=$2
	`, orgID, userID).Scan(&role)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", httputil.ErrNotFound
		}
		return "", err
	}
	if write && role == "viewer" {
		return "", httputil.ErrForbidden
	}
	return role, nil
}

func OrgIDParam(r *http.Request) string {
	return chi.URLParam(r, "orgID")
}
