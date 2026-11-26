package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bugcode-shield/internal/ai"
	"bugcode-shield/internal/auth"
	"bugcode-shield/internal/config"
	"bugcode-shield/internal/crypto"
	"bugcode-shield/internal/db"
	"bugcode-shield/internal/finding"
	"bugcode-shield/internal/health"
	"bugcode-shield/internal/live"
	"bugcode-shield/internal/org"
	"bugcode-shield/internal/platform"
	"bugcode-shield/internal/project"
	"bugcode-shield/internal/queue"
	"bugcode-shield/internal/scan"
	"bugcode-shield/internal/server"
	"bugcode-shield/internal/settings"
	"bugcode-shield/internal/source"

	"github.com/minio/minio-go/v7"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.LogFormat)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	clients, err := platform.New(cfg)
	if err != nil {
		logger.Error("failed to initialize platform clients", "error", err)
		os.Exit(1)
	}
	defer clients.Close()

	if err := db.Migrate(ctx, clients.Postgres); err != nil {
		logger.Error("migration failed", "error", err)
		os.Exit(1)
	}

	exists, err := clients.MinIO.BucketExists(ctx, cfg.MinIOBucket)
	if err != nil {
		logger.Error("minio bucket check failed", "error", err)
		os.Exit(1)
	}
	if !exists {
		if err := clients.MinIO.MakeBucket(ctx, cfg.MinIOBucket, minio.MakeBucketOptions{}); err != nil {
			logger.Error("minio bucket create failed", "error", err)
			os.Exit(1)
		}
	}

	encKey, err := crypto.ParseKey(cfg.EncryptionKey)
	if err != nil {
		logger.Error("invalid ENCRYPTION_KEY", "error", err)
		os.Exit(1)
	}

	authSvc := auth.New(clients.Postgres, cfg.JWTSecret, 24*time.Hour)
	orgs := org.New(clients.Postgres)
	projects := project.New(clients.Postgres, orgs, clients.MinIO, cfg.MinIOBucket, cfg.ScanSources, cfg.ScanHostSources, cfg.ScanWorkspace)
	settingsSvc := settings.New(clients.Postgres, encKey)
	sources := source.New(clients.Postgres, orgs, clients.MinIO, cfg.MinIOBucket, encKey, source.Paths{
		HostHome:      cfg.ScanHostHome,
		ContainerHome: cfg.ScanContainerHome,
		SourcesDir:    cfg.ScanSources,
		HostSources:   cfg.ScanHostSources,
	}, settingsSvc)
	q := queue.New(cfg.RabbitMQURL())
	events := live.New(clients.Redis)
	go events.Serve(ctx)
	scans := scan.New(clients.Postgres, orgs, q, events, authSvc)
	findings := finding.New(clients.Postgres, orgs)
	aiSvc := ai.New(findings, settingsSvc, cfg.OpenAIAPIKey, cfg.OpenAIBaseURL, cfg.OpenAIModel)
	checker := health.New(clients)

	srv := server.New(cfg, logger, checker, server.Deps{
		Auth:     authSvc,
		Orgs:     orgs,
		Projects: projects,
		Sources:  sources,
		Scans:    scans,
		Findings: findings,
		AI:       aiSvc,
		Settings: settingsSvc,
	})

	go func() {
		logger.Info("api listening", "addr", cfg.HTTPAddr, "env", cfg.AppEnv)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server stopped", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
}

func newLogger(format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if format == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}
