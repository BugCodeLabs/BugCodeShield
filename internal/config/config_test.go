package config

import (
	"testing"
)

func TestLoadRequiresSecrets(t *testing.T) {
	t.Setenv("POSTGRES_HOST", "")
	t.Setenv("POSTGRES_USER", "")
	t.Setenv("POSTGRES_PASSWORD", "")
	t.Setenv("POSTGRES_DB", "")
	t.Setenv("REDIS_HOST", "")
	t.Setenv("REDIS_PASSWORD", "")
	t.Setenv("RABBITMQ_HOST", "")
	t.Setenv("RABBITMQ_USER", "")
	t.Setenv("RABBITMQ_PASSWORD", "")
	t.Setenv("MINIO_ENDPOINT", "")
	t.Setenv("MINIO_ROOT_USER", "")
	t.Setenv("MINIO_ROOT_PASSWORD", "")
	t.Setenv("JWT_SECRET", "")
	t.Setenv("ENCRYPTION_KEY", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected missing environment variables to fail")
	}
}

func TestLoadSucceedsWithRequiredVars(t *testing.T) {
	t.Setenv("POSTGRES_HOST", "postgres")
	t.Setenv("POSTGRES_USER", "bugcodeshield")
	t.Setenv("POSTGRES_PASSWORD", "secret")
	t.Setenv("POSTGRES_DB", "bugcodeshield")
	t.Setenv("REDIS_HOST", "redis")
	t.Setenv("REDIS_PASSWORD", "secret")
	t.Setenv("RABBITMQ_HOST", "rabbitmq")
	t.Setenv("RABBITMQ_USER", "bugcodeshield")
	t.Setenv("RABBITMQ_PASSWORD", "secret")
	t.Setenv("MINIO_ENDPOINT", "minio:9000")
	t.Setenv("MINIO_ROOT_USER", "bugcodeshield")
	t.Setenv("MINIO_ROOT_PASSWORD", "secret-secret")
	t.Setenv("JWT_SECRET", "test-jwt-secret-which-is-long-enough")
	t.Setenv("ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPAddr != ":3000" {
		t.Fatalf("HTTPAddr = %q", cfg.HTTPAddr)
	}
	if cfg.RedisAddr() != "redis:6379" {
		t.Fatalf("RedisAddr = %q", cfg.RedisAddr())
	}
}

func TestGetenvBoolRejectsGarbage(t *testing.T) {
	t.Setenv("MINIO_USE_SSL", "not-a-bool")
	t.Setenv("POSTGRES_HOST", "postgres")
	t.Setenv("POSTGRES_USER", "bugcodeshield")
	t.Setenv("POSTGRES_PASSWORD", "secret")
	t.Setenv("POSTGRES_DB", "bugcodeshield")
	t.Setenv("REDIS_HOST", "redis")
	t.Setenv("REDIS_PASSWORD", "secret")
	t.Setenv("RABBITMQ_HOST", "rabbitmq")
	t.Setenv("RABBITMQ_USER", "bugcodeshield")
	t.Setenv("RABBITMQ_PASSWORD", "secret")
	t.Setenv("MINIO_ENDPOINT", "minio:9000")
	t.Setenv("MINIO_ROOT_USER", "bugcodeshield")
	t.Setenv("MINIO_ROOT_PASSWORD", "secret-secret")
	t.Setenv("JWT_SECRET", "test-jwt-secret-which-is-long-enough")
	t.Setenv("ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	_, err := Load()
	if err == nil {
		t.Fatal("expected invalid boolean to fail")
	}
}
