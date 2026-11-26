package project

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"bugcode-shield/internal/auth"
	"bugcode-shield/internal/httputil"

	"github.com/go-chi/chi/v5"
	"github.com/minio/minio-go/v7"
)

type deleteRequest struct {
	Name string `json:"name"`
}

func ConfirmProjectName(typed, actual string) bool {
	return strings.TrimSpace(typed) != "" && strings.TrimSpace(typed) == actual
}

func (s *Service) Delete(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	projectID := chi.URLParam(r, "projectID")
	if _, err := s.orgs.RequireProjectAccess(r.Context(), userID, projectID, true); err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	var req deleteRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", "Invalid JSON body")
		return
	}
	var name string
	err := s.pool.QueryRow(r.Context(), `SELECT name FROM projects WHERE id=$1`, projectID).Scan(&name)
	if err != nil {
		httputil.WriteAppError(w, httputil.ErrNotFound)
		return
	}
	if !ConfirmProjectName(req.Name, name) {
		httputil.Error(w, http.StatusBadRequest, "validation", "Type the project name exactly to confirm deletion")
		return
	}

	scanIDs, storageKeys, sourceDirs, err := s.collectCleanup(r.Context(), projectID)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}

	_, _ = s.pool.Exec(r.Context(), `
		UPDATE scans
		SET status='CANCELLED', finished_at=now(), error_message='Project deleted'
		WHERE project_id=$1 AND status IN ('QUEUED', 'PREPARING', 'RUNNING')
	`, projectID)

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	defer tx.Rollback(r.Context())

	if _, err := tx.Exec(r.Context(), `DELETE FROM findings WHERE project_id=$1`, projectID); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	if _, err := tx.Exec(r.Context(), `
		DELETE FROM scan_logs WHERE scan_id IN (SELECT id FROM scans WHERE project_id=$1)
	`, projectID); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	if _, err := tx.Exec(r.Context(), `DELETE FROM scans WHERE project_id=$1`, projectID); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	if _, err := tx.Exec(r.Context(), `DELETE FROM project_sources WHERE project_id=$1`, projectID); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	tag, err := tx.Exec(r.Context(), `DELETE FROM projects WHERE id=$1`, projectID)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteAppError(w, httputil.ErrNotFound)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}

	s.removeStoredFiles(r.Context(), storageKeys, sourceDirs, scanIDs)
	httputil.JSON(w, http.StatusOK, map[string]any{"deleted": true, "id": projectID})
}

func (s *Service) collectCleanup(ctx context.Context, projectID string) (scanIDs, storageKeys, sourceDirs []string, err error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text FROM scans WHERE project_id=$1`, projectID)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, nil, nil, err
		}
		scanIDs = append(scanIDs, id)
	}

	srcRows, err := s.pool.Query(ctx, `SELECT storage_key, local_path FROM project_sources WHERE project_id=$1`, projectID)
	if err != nil {
		return nil, nil, nil, err
	}
	defer srcRows.Close()
	seenDir := map[string]struct{}{}
	for srcRows.Next() {
		var key, localPath *string
		if err := srcRows.Scan(&key, &localPath); err != nil {
			return nil, nil, nil, err
		}
		if key != nil && strings.TrimSpace(*key) != "" {
			storageKeys = append(storageKeys, strings.TrimSpace(*key))
		}
		if dir := s.storedSourceDir(localPath); dir != "" {
			if _, ok := seenDir[dir]; !ok {
				seenDir[dir] = struct{}{}
				sourceDirs = append(sourceDirs, dir)
			}
		}
	}
	return scanIDs, storageKeys, sourceDirs, nil
}

func (s *Service) storedSourceDir(localPath *string) string {
	if localPath == nil || s.hostSources == "" || s.sourcesDir == "" {
		return ""
	}
	clean := filepath.Clean(*localPath)
	host := filepath.Clean(s.hostSources)
	sep := string(os.PathSeparator)
	if clean != host && !strings.HasPrefix(clean+sep, host+sep) {
		return ""
	}
	rel, err := filepath.Rel(host, clean)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return ""
	}
	first, _, _ := strings.Cut(filepath.ToSlash(rel), "/")
	if first == "" || first == "." || first == ".." {
		return ""
	}
	return filepath.Join(s.sourcesDir, first)
}

func (s *Service) removeStoredFiles(ctx context.Context, storageKeys, sourceDirs, scanIDs []string) {
	if s.minio != nil && s.bucket != "" {
		for _, key := range storageKeys {
			_ = s.minio.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
		}
	}
	for _, dir := range sourceDirs {
		_ = os.RemoveAll(dir)
	}
	if strings.TrimSpace(s.workspace) == "" {
		return
	}
	root := filepath.Clean(s.workspace)
	for _, id := range scanIDs {
		id = strings.TrimSpace(id)
		if id == "" || strings.Contains(id, "/") || strings.Contains(id, "\\") || strings.Contains(id, "..") {
			continue
		}
		_ = os.RemoveAll(filepath.Join(root, id))
	}
}
