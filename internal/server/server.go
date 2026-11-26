package server

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"bugcode-shield/internal/ai"
	"bugcode-shield/internal/auth"
	"bugcode-shield/internal/config"
	"bugcode-shield/internal/finding"
	"bugcode-shield/internal/health"
	"bugcode-shield/internal/httputil"
	"bugcode-shield/internal/org"
	"bugcode-shield/internal/project"
	"bugcode-shield/internal/scan"
	"bugcode-shield/internal/settings"
	"bugcode-shield/internal/source"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

type Deps struct {
	Auth     *auth.Service
	Orgs     *org.Service
	Projects *project.Service
	Sources  *source.Service
	Scans    *scan.Service
	Findings *finding.Service
	AI       *ai.Service
	Settings *settings.Service
}

func New(cfg config.Config, logger *slog.Logger, checker *health.Checker, deps Deps) *http.Server {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(requestLogger(logger))
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000", "http://127.0.0.1:3000"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		httputil.JSON(w, http.StatusOK, map[string]string{
			"name":    "bugcodeshield-api",
			"version": cfg.AppVersion,
		})
	})
	r.Get("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		httputil.JSON(w, http.StatusOK, checker.Live())
	})
	r.Get("/health", checker.ReadyHandler())
	r.Get("/health/ready", checker.ReadyHandler())

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/auth/register", deps.Auth.Register)
		r.Post("/auth/login", deps.Auth.Login)
		r.Get("/scans/{scanID}/ws", deps.Scans.Stream)

		r.Group(func(r chi.Router) {
			r.Use(deps.Auth.Middleware)
			r.Get("/auth/me", deps.Auth.Me)
			r.Patch("/auth/me", deps.Auth.UpdateMe)
			r.Get("/settings", deps.Settings.Get)
			r.Put("/settings", deps.Settings.Update)

			r.Get("/orgs", deps.Orgs.List)
			r.Post("/orgs", deps.Orgs.Create)

			r.Get("/orgs/{orgID}/projects", deps.Projects.List)
			r.Post("/orgs/{orgID}/projects", deps.Projects.Create)
			r.Get("/projects", deps.Projects.ListMine)
			r.Get("/projects/{projectID}", deps.Projects.Get)
			r.Get("/projects/{projectID}/summary", deps.Findings.Summary)

			r.Get("/projects/{projectID}/sources", deps.Sources.List)
			r.Post("/projects/{projectID}/sources/zip", deps.Sources.UploadZip)
			r.Post("/projects/{projectID}/sources/files", deps.Sources.UploadFiles)
			r.Post("/projects/{projectID}/sources/local", deps.Sources.ConnectLocal)
			r.Post("/projects/{projectID}/sources/github", deps.Sources.ConnectGitHub)

			r.Post("/projects/{projectID}/scans", deps.Scans.Create)
			r.Get("/projects/{projectID}/scans", deps.Scans.List)
			r.Get("/scans/{scanID}", deps.Scans.Get)
			r.Post("/scans/{scanID}/cancel", deps.Scans.Cancel)
			r.Get("/scans/{scanID}/logs", deps.Scans.Logs)
			r.Get("/scans/{scanID}/findings", deps.Findings.List)
			r.Get("/scans/{scanID}/export.json", deps.Findings.ExportJSON)
			r.Get("/scans/{scanID}/export.sarif", deps.Findings.ExportSARIF)
			r.Post("/findings/{findingID}/explain", deps.AI.Explain)
		})
	})

	return &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
	}
}

func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				logger.Info("request",
					"method", r.Method,
					"path", r.URL.Path,
					"upgrade", "websocket",
					"request_id", middleware.GetReqID(r.Context()),
				)
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", middleware.GetReqID(r.Context()),
			)
		})
	}
}
