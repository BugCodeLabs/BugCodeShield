package source

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"bugcode-shield/internal/auth"
	"bugcode-shield/internal/crypto"
	"bugcode-shield/internal/httputil"
	"bugcode-shield/internal/org"
	"bugcode-shield/internal/settings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
)

type Source struct {
	ID           string        `json:"id"`
	ProjectID    string        `json:"project_id"`
	Kind         string        `json:"kind"`
	VersionLabel string        `json:"version_label"`
	StorageKey   *string       `json:"storage_key,omitempty"`
	GitHubRepo   *string       `json:"github_repo,omitempty"`
	GitHubRef    *string       `json:"github_ref,omitempty"`
	CommitSHA    *string       `json:"commit_sha,omitempty"`
	LocalPath    *string       `json:"local_path,omitempty"`
	FileCount    int           `json:"file_count"`
	ByteSize     int64         `json:"byte_size"`
	CreatedAt    time.Time     `json:"created_at"`
	Status       string        `json:"status,omitempty"`
	Message      string        `json:"message,omitempty"`
	Matches      []FolderMatch `json:"matches,omitempty"`
}

type Service struct {
	pool     *pgxpool.Pool
	orgs     *org.Service
	minio    *minio.Client
	bucket   string
	encKey   []byte
	paths    Paths
	settings *settings.Service
}

func New(pool *pgxpool.Pool, orgs *org.Service, mc *minio.Client, bucket string, encKey []byte, paths Paths, creds *settings.Service) *Service {
	return &Service{pool: pool, orgs: orgs, minio: mc, bucket: bucket, encKey: encKey, paths: paths, settings: creds}
}

func (s *Service) List(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	projectID := chi.URLParam(r, "projectID")
	if _, err := s.orgs.RequireProjectAccess(r.Context(), userID, projectID, false); err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	rows, err := s.pool.Query(r.Context(), `
		SELECT id::text, project_id::text, kind, version_label, storage_key, github_repo, github_ref, commit_sha, local_path, file_count, byte_size, created_at
		FROM project_sources WHERE project_id=$1 ORDER BY created_at DESC
	`, projectID)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	defer rows.Close()
	items := make([]Source, 0)
	for rows.Next() {
		var src Source
		if err := rows.Scan(&src.ID, &src.ProjectID, &src.Kind, &src.VersionLabel, &src.StorageKey, &src.GitHubRepo, &src.GitHubRef, &src.CommitSHA, &src.LocalPath, &src.FileCount, &src.ByteSize, &src.CreatedAt); err != nil {
			httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
			return
		}
		items = append(items, src)
	}
	httputil.JSON(w, http.StatusOK, map[string]any{"sources": items})
}

func (s *Service) UploadZip(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	projectID := chi.URLParam(r, "projectID")
	if _, err := s.orgs.RequireProjectAccess(r.Context(), userID, projectID, true); err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxArchiveBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", "ZIP is missing or larger than 512MB")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", "file field is required")
		return
	}
	defer file.Close()
	if !strings.HasSuffix(strings.ToLower(header.Filename), ".zip") {
		httputil.Error(w, http.StatusBadRequest, "validation", "Only .zip archives are accepted")
		return
	}
	if strings.TrimSpace(s.paths.SourcesDir) == "" || strings.TrimSpace(s.paths.HostSources) == "" {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Local source storage is not configured")
		return
	}
	id := uuid.NewString()
	storeDir := filepath.Join(s.paths.SourcesDir, id)
	if err := os.MkdirAll(filepath.Join(storeDir, "src"), 0o755); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Failed to prepare extract folder")
		return
	}
	zipPath := filepath.Join(storeDir, "archive.zip")
	out, err := os.Create(zipPath)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Failed to store archive")
		return
	}
	size, copyErr := io.Copy(out, file)
	_ = out.Close()
	if copyErr != nil {
		_ = os.RemoveAll(storeDir)
		httputil.Error(w, http.StatusBadRequest, "validation", "ZIP is missing or larger than 512MB")
		return
	}
	extractDir := filepath.Join(storeDir, "src")
	count, err := SafeExtractZipFile(zipPath, extractDir)
	if err != nil {
		_ = os.RemoveAll(storeDir)
		httputil.WriteAppError(w, err)
		return
	}
	hostSrc := filepath.Join(s.paths.HostSources, id, "src")
	src, err := s.insert(r.Context(), projectID, userID, "zip", header.Filename, nil, nil, nil, nil, &hostSrc, count, size, nil)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	src.Status = "extracted"
	src.Message = fmt.Sprintf("Extracted %s on this computer (%d files, %s). Scanning from disk, not from the browser.", header.Filename, count, formatBytes(size))
	httputil.JSON(w, http.StatusCreated, src)
}

func (s *Service) UploadFiles(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	projectID := chi.URLParam(r, "projectID")
	if _, err := s.orgs.RequireProjectAccess(r.Context(), userID, projectID, true); err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", "Folder upload is too large. Paste the folder path instead so BugCode Shield can scan it in place.")
		return
	}
	tmp, err := os.MkdirTemp("", "bugcodeshield-files-*")
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	defer os.RemoveAll(tmp)

	files := r.MultipartForm.File["files"]
	paths := r.MultipartForm.Value["paths"]
	if len(files) == 0 {
		httputil.Error(w, http.StatusBadRequest, "validation", "files field is required")
		return
	}
	folderName := "project-folder"
	if len(paths) > 0 {
		rel := strings.ReplaceAll(paths[0], "\\", "/")
		if i := strings.Index(rel, "/"); i > 0 {
			folderName = rel[:i]
		}
	}
	stored := 0
	for i, fh := range files {
		rel := strings.ReplaceAll(fh.Filename, "\\", "/")
		if i < len(paths) && strings.TrimSpace(paths[i]) != "" {
			rel = strings.ReplaceAll(paths[i], "\\", "/")
		}
		if strings.Contains(rel, "..") || strings.HasPrefix(rel, "/") {
			httputil.Error(w, http.StatusBadRequest, "validation", "illegal file path")
			return
		}
		if shouldSkip(rel) {
			continue
		}
		target, err := safeJoin(tmp, rel)
		if err != nil {
			httputil.WriteAppError(w, err)
			return
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
			return
		}
		in, err := fh.Open()
		if err != nil {
			httputil.Error(w, http.StatusBadRequest, "validation", "unable to read uploaded file")
			return
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
		if err != nil {
			_ = in.Close()
			httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
			return
		}
		_, copyErr := io.Copy(out, io.LimitReader(in, 2<<20))
		_ = in.Close()
		_ = out.Close()
		if copyErr != nil {
			httputil.Error(w, http.StatusBadRequest, "validation", "unable to store uploaded file")
			return
		}
		stored++
		if stored > MaxFileCount {
			httputil.Error(w, http.StatusBadRequest, "validation", "Too many files in this folder (8000 max after skipping node_modules/.git)")
			return
		}
	}
	raw, count, err := ZipDirectory(tmp)
	if err != nil || count == 0 {
		httputil.Error(w, http.StatusBadRequest, "validation", "No usable files were uploaded")
		return
	}
	key := path.Join("projects", projectID, "sources", uuid.NewString()+".zip")
	if _, err := s.minio.PutObject(r.Context(), s.bucket, key, bytes.NewReader(raw), int64(len(raw)), minio.PutObjectOptions{ContentType: "application/zip"}); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Failed to store files")
		return
	}
	src, err := s.insert(r.Context(), projectID, userID, "files", folderName, &key, nil, nil, nil, nil, count, int64(len(raw)), nil)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	src.Status = "uploaded"
	src.Message = fmt.Sprintf("Added folder %s (%d files, %s)", folderName, count, formatBytes(int64(len(raw))))
	httputil.JSON(w, http.StatusCreated, src)
}

type githubRequest struct {
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
	Token      string `json:"token"`
}

func (s *Service) ConnectGitHub(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	projectID := chi.URLParam(r, "projectID")
	if _, err := s.orgs.RequireProjectAccess(r.Context(), userID, projectID, true); err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	var req githubRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", "Invalid JSON body")
		return
	}
	repo := NormalizeGitHubRepo(req.Repository)
	if !validGitHubRepo(repo) {
		httputil.Error(w, http.StatusBadRequest, "validation", "Repository must look like owner/name or a github.com URL")
		return
	}
	ref := strings.TrimSpace(req.Ref)
	if ref == "" {
		ref = "main"
	}
	plainToken := strings.TrimSpace(req.Token)
	if plainToken == "" && s.settings != nil {
		saved, tokenErr := s.settings.GitHubToken(r.Context(), userID)
		if tokenErr != nil {
			httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
			return
		}
		plainToken = strings.TrimSpace(saved)
	}
	sha, err := verifyGitHubRepo(r.Context(), repo, ref, plainToken)
	if err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	var tokenCipher []byte
	if plainToken != "" {
		enc, encErr := crypto.Encrypt(s.encKey, []byte(plainToken))
		if encErr != nil {
			httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
			return
		}
		tokenCipher = enc
	}
	var shaPtr *string
	if sha != "" {
		shaPtr = &sha
	}
	if existing, ok, lookErr := s.lookupGitHub(r.Context(), projectID, repo, ref); lookErr != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	} else if ok {
		_, _ = s.pool.Exec(r.Context(), `UPDATE project_sources SET commit_sha=$2, token_ciphertext=COALESCE($3, token_ciphertext) WHERE id=$1`, existing.ID, shaPtr, nullBytes(tokenCipher))
		existing.CommitSHA = shaPtr
		existing.Status = "connected"
		existing.Message = "Reusing saved github.com/" + repo + " on branch " + ref + ". Start scan — do not add the same repository again."
		httputil.JSON(w, http.StatusOK, existing)
		return
	}
	src, err := s.insert(r.Context(), projectID, userID, "github", repo+"@"+ref, nil, &repo, &ref, shaPtr, nil, 0, 0, tokenCipher)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	src.Status = "connected"
	src.Message = "Connected github.com/" + repo + " on branch " + ref
	if sha != "" {
		short := sha
		if len(short) > 7 {
			short = short[:7]
		}
		src.Message += " (commit " + short + ")"
	}
	httputil.JSON(w, http.StatusCreated, src)
}

func (s *Service) ConnectLocal(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	projectID := chi.URLParam(r, "projectID")
	if _, err := s.orgs.RequireProjectAccess(r.Context(), userID, projectID, true); err != nil {
		httputil.WriteAppError(w, err)
		return
	}
	var req struct {
		Path     string   `json:"path"`
		Name     string   `json:"name"`
		Children []string `json:"children"`
	}
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", "Invalid JSON body")
		return
	}
	hostPath := strings.TrimSpace(req.Path)
	if hostPath == "" && strings.TrimSpace(req.Name) == "" {
		httputil.Error(w, http.StatusBadRequest, "validation", "Choose a folder")
		return
	}
	if hostPath == "" {
		picked, matches, err := s.paths.PickFolder(req.Name, req.Children)
		if err != nil {
			httputil.Error(w, http.StatusBadRequest, "validation", err.Error())
			return
		}
		if picked == "" {
			httputil.JSON(w, http.StatusOK, Source{
				Status:  "choose",
				Message: fmt.Sprintf("Several folders named %s were found. Pick the one to scan. Files were not uploaded.", req.Name),
				Matches: matches,
			})
			return
		}
		hostPath = picked
	}
	resolvedHost, viewPath, err := s.paths.Resolve(hostPath)
	if err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	count, bytes, err := CountScanFiles(viewPath)
	if err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", "Could not read that folder")
		return
	}
	if count == 0 {
		httputil.Error(w, http.StatusBadRequest, "validation", "No source files found in that folder (node_modules/.git are skipped)")
		return
	}
	label := filepath.Base(resolvedHost)
	if existing, ok, lookErr := s.lookupLocal(r.Context(), projectID, resolvedHost); lookErr != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	} else if ok {
		_, _ = s.pool.Exec(r.Context(), `UPDATE project_sources SET file_count=$2, byte_size=$3 WHERE id=$1`, existing.ID, count, bytes)
		existing.FileCount = count
		existing.ByteSize = bytes
		existing.Status = "local"
		existing.Message = fmt.Sprintf("Reusing saved folder %s (%d files, %s). Start scan — adding the same path again does not make scans faster.", resolvedHost, count, formatBytes(bytes))
		httputil.JSON(w, http.StatusOK, existing)
		return
	}
	src, err := s.insert(r.Context(), projectID, userID, "local", label, nil, nil, nil, nil, &resolvedHost, count, bytes, nil)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	src.Status = "local"
	src.Message = fmt.Sprintf("Using %s in place (%d files, %s). The project was not uploaded.", resolvedHost, count, formatBytes(bytes))
	httputil.JSON(w, http.StatusCreated, src)
}

func (s *Service) lookupLocal(ctx context.Context, projectID, path string) (Source, bool, error) {
	src, err := s.lookupSource(ctx, `
		SELECT id::text, project_id::text, kind, version_label, storage_key, github_repo, github_ref, commit_sha, local_path, file_count, byte_size, created_at
		FROM project_sources WHERE project_id=$1 AND kind IN ('local','zip') AND local_path=$2
		ORDER BY created_at DESC LIMIT 1
	`, projectID, path)
	if err == pgx.ErrNoRows {
		return Source{}, false, nil
	}
	if err != nil {
		return Source{}, false, err
	}
	return src, true, nil
}

func (s *Service) lookupGitHub(ctx context.Context, projectID, repo, ref string) (Source, bool, error) {
	src, err := s.lookupSource(ctx, `
		SELECT id::text, project_id::text, kind, version_label, storage_key, github_repo, github_ref, commit_sha, local_path, file_count, byte_size, created_at
		FROM project_sources WHERE project_id=$1 AND kind='github' AND github_repo=$2 AND github_ref=$3
		ORDER BY created_at DESC LIMIT 1
	`, projectID, repo, ref)
	if err == pgx.ErrNoRows {
		return Source{}, false, nil
	}
	if err != nil {
		return Source{}, false, err
	}
	return src, true, nil
}

func (s *Service) lookupSource(ctx context.Context, q string, args ...any) (Source, error) {
	var src Source
	err := s.pool.QueryRow(ctx, q, args...).Scan(&src.ID, &src.ProjectID, &src.Kind, &src.VersionLabel, &src.StorageKey, &src.GitHubRepo, &src.GitHubRef, &src.CommitSHA, &src.LocalPath, &src.FileCount, &src.ByteSize, &src.CreatedAt)
	return src, err
}

func nullBytes(v []byte) any {
	if len(v) == 0 {
		return nil
	}
	return v
}

func (s *Service) insert(ctx context.Context, projectID, userID, kind, label string, key, repo, ref, commit, localPath *string, count int, size int64, token []byte) (Source, error) {
	var src Source
	err := s.pool.QueryRow(ctx, `
		INSERT INTO project_sources (project_id, kind, version_label, storage_key, github_repo, github_ref, commit_sha, local_path, token_ciphertext, file_count, byte_size, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id::text, project_id::text, kind, version_label, storage_key, github_repo, github_ref, commit_sha, local_path, file_count, byte_size, created_at
	`, projectID, kind, label, key, repo, ref, commit, localPath, token, count, size, userID).Scan(
		&src.ID, &src.ProjectID, &src.Kind, &src.VersionLabel, &src.StorageKey, &src.GitHubRepo, &src.GitHubRef, &src.CommitSHA, &src.LocalPath, &src.FileCount, &src.ByteSize, &src.CreatedAt,
	)
	return src, err
}

func formatBytes(n int64) string {
	switch {
	case n < 1024:
		return strconv.FormatInt(n, 10) + " B"
	case n < 1024*1024:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", float64(n)/1024), ".0") + " KB"
	default:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", float64(n)/(1024*1024)), ".0") + " MB"
	}
}

func validGitHubRepo(repo string) bool {
	repo = strings.TrimPrefix(repo, "https://github.com/")
	repo = strings.TrimPrefix(repo, "http://github.com/")
	repo = strings.TrimPrefix(repo, "git@github.com:")
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return false
	}
	for _, p := range parts {
		if p == "" || strings.ContainsAny(p, " \t") {
			return false
		}
	}
	return true
}

func NormalizeGitHubRepo(repo string) string {
	repo = strings.TrimSpace(repo)
	repo = strings.TrimSuffix(repo, ".git")
	repo = strings.TrimPrefix(repo, "https://github.com/")
	repo = strings.TrimPrefix(repo, "http://github.com/")
	repo = strings.TrimPrefix(repo, "git@github.com:")
	return repo
}
