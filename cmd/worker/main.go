package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"bugcode-shield/internal/config"
	"bugcode-shield/internal/crypto"
	"bugcode-shield/internal/db"
	"bugcode-shield/internal/finding"
	"bugcode-shield/internal/live"
	"bugcode-shield/internal/org"
	"bugcode-shield/internal/platform"
	"bugcode-shield/internal/queue"
	"bugcode-shield/internal/scan"
	"bugcode-shield/internal/worker"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	clients, err := platform.New(cfg)
	if err != nil {
		logger.Error("platform", "error", err)
		os.Exit(1)
	}
	defer clients.Close()

	if err := db.Migrate(ctx, clients.Postgres); err != nil {
		logger.Error("migration failed", "error", err)
		os.Exit(1)
	}
	encKey, err := crypto.ParseKey(cfg.EncryptionKey)
	if err != nil {
		logger.Error("invalid ENCRYPTION_KEY", "error", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(cfg.ScanWorkspace, 0o755); err != nil {
		logger.Error("workspace", "error", err)
		os.Exit(1)
	}
	hostCache := cfg.ScanHostCache
	if hostCache == "" {
		hostCache = filepath.Join(filepath.Dir(cfg.ScanHostWorkspace), "cache")
	}
	_ = os.MkdirAll(filepath.Join(filepath.Dir(cfg.ScanWorkspace), "cache"), 0o777)

	orgs := org.New(clients.Postgres)
	q := queue.New(cfg.RabbitMQURL())
	events := live.New(clients.Redis)
	scans := scan.New(clients.Postgres, orgs, q, events, nil)
	findings := finding.New(clients.Postgres, orgs)
	w := worker.New(clients.Postgres, clients.MinIO, scans, findings, events, worker.Config{
		Workspace:     cfg.ScanWorkspace,
		HostWorkspace: cfg.ScanHostWorkspace,
		HostCache:     hostCache,
		Network:       cfg.ScannerNetwork,
		EncKey:        encKey,
		Bucket:        cfg.MinIOBucket,
		SonarURL:      cfg.SonarQubeURL,
		SonarPassword: cfg.SonarQubePassword,
	}, logger)

	logger.Info("worker consuming scan jobs")
	if err := q.Consume(ctx, w.Handle); err != nil && ctx.Err() == nil {
		logger.Error("consumer stopped", "error", err)
		os.Exit(1)
	}
}
