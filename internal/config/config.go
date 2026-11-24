package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	AppEnv     string
	AppVersion string
	HTTPAddr   string
	LogFormat  string

	PostgresHost     string
	PostgresPort     int
	PostgresUser     string
	PostgresPassword string
	PostgresDB       string
	PostgresSSLMode  string

	RedisHost     string
	RedisPort     int
	RedisPassword string
	RedisDB       int

	RabbitMQHost     string
	RabbitMQPort     int
	RabbitMQUser     string
	RabbitMQPassword string
	RabbitMQVHost    string

	MinIOEndpoint  string
	MinIOAccessKey string
	MinIOSecretKey string
	MinIOUseSSL    bool
	MinIOBucket    string

	JWTSecret         string
	EncryptionKey     string
	ScanWorkspace     string
	ScanHostWorkspace string
	ScanHostCache     string
	ScanHostHome      string
	ScanContainerHome string
	ScanSources       string
	ScanHostSources   string
	ScannerNetwork    string
	SonarQubeURL      string
	SonarQubePassword string
	OpenAIAPIKey      string
	OpenAIBaseURL     string
	OpenAIModel       string
}

func Load() (Config, error) {
	cfg := Config{
		AppEnv:     getenv("APP_ENV", "development"),
		AppVersion: getenv("APP_VERSION", "0.1.0"),
		HTTPAddr:   getenv("HTTP_ADDR", ":3000"),
		LogFormat:  getenv("LOG_FORMAT", "json"),

		PostgresHost:     os.Getenv("POSTGRES_HOST"),
		PostgresUser:     os.Getenv("POSTGRES_USER"),
		PostgresPassword: os.Getenv("POSTGRES_PASSWORD"),
		PostgresDB:       os.Getenv("POSTGRES_DB"),
		PostgresSSLMode:  getenv("POSTGRES_SSLMODE", "disable"),

		RedisHost:     os.Getenv("REDIS_HOST"),
		RedisPassword: os.Getenv("REDIS_PASSWORD"),

		RabbitMQHost:     os.Getenv("RABBITMQ_HOST"),
		RabbitMQUser:     os.Getenv("RABBITMQ_USER"),
		RabbitMQPassword: os.Getenv("RABBITMQ_PASSWORD"),
		RabbitMQVHost:    getenv("RABBITMQ_VHOST", "/"),

		MinIOEndpoint:  os.Getenv("MINIO_ENDPOINT"),
		MinIOAccessKey: os.Getenv("MINIO_ROOT_USER"),
		MinIOSecretKey: os.Getenv("MINIO_ROOT_PASSWORD"),
		MinIOBucket:    getenv("MINIO_BUCKET", "bugcodeshield"),

		JWTSecret:         os.Getenv("JWT_SECRET"),
		EncryptionKey:     os.Getenv("ENCRYPTION_KEY"),
		ScanWorkspace:     getenv("SCAN_WORKSPACE", "/var/lib/bugcodeshield/scans"),
		ScanHostWorkspace: getenv("SCAN_HOST_WORKSPACE", "./data/scans"),
		ScanHostCache:     os.Getenv("SCAN_HOST_CACHE"),
		ScanHostHome:      os.Getenv("SCAN_HOST_HOME"),
		ScanContainerHome: getenv("SCAN_CONTAINER_HOME", "/host-home"),
		ScanSources:       getenv("SCAN_SOURCES", "/var/lib/bugcodeshield/sources"),
		ScanHostSources:   os.Getenv("SCAN_HOST_SOURCES"),
		ScannerNetwork:    os.Getenv("SCANNER_NETWORK"),
		SonarQubeURL:      os.Getenv("SONARQUBE_URL"),
		SonarQubePassword: os.Getenv("SONARQUBE_ADMIN_PASSWORD"),
		OpenAIAPIKey:      os.Getenv("OPENAI_API_KEY"),
		OpenAIBaseURL:     getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
		OpenAIModel:       getenv("OPENAI_MODEL", "gpt-4o-mini"),
	}

	var err error
	cfg.PostgresPort, err = getenvInt("POSTGRES_PORT", 5432)
	if err != nil {
		return Config{}, err
	}
	cfg.RedisPort, err = getenvInt("REDIS_PORT", 6379)
	if err != nil {
		return Config{}, err
	}
	cfg.RedisDB, err = getenvInt("REDIS_DB", 0)
	if err != nil {
		return Config{}, err
	}
	cfg.RabbitMQPort, err = getenvInt("RABBITMQ_PORT", 5672)
	if err != nil {
		return Config{}, err
	}
	cfg.MinIOUseSSL, err = getenvBool("MINIO_USE_SSL", false)
	if err != nil {
		return Config{}, err
	}

	required := map[string]string{
		"POSTGRES_HOST":       cfg.PostgresHost,
		"POSTGRES_USER":       cfg.PostgresUser,
		"POSTGRES_PASSWORD":   cfg.PostgresPassword,
		"POSTGRES_DB":         cfg.PostgresDB,
		"REDIS_HOST":          cfg.RedisHost,
		"REDIS_PASSWORD":      cfg.RedisPassword,
		"RABBITMQ_HOST":       cfg.RabbitMQHost,
		"RABBITMQ_USER":       cfg.RabbitMQUser,
		"RABBITMQ_PASSWORD":   cfg.RabbitMQPassword,
		"MINIO_ENDPOINT":      cfg.MinIOEndpoint,
		"MINIO_ROOT_USER":     cfg.MinIOAccessKey,
		"MINIO_ROOT_PASSWORD": cfg.MinIOSecretKey,
		"JWT_SECRET":          cfg.JWTSecret,
		"ENCRYPTION_KEY":      cfg.EncryptionKey,
	}
	var missing []string
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	return cfg, nil
}

func (c Config) PostgresDSN() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.PostgresUser,
		c.PostgresPassword,
		c.PostgresHost,
		c.PostgresPort,
		c.PostgresDB,
		c.PostgresSSLMode,
	)
}

func (c Config) RedisAddr() string {
	return fmt.Sprintf("%s:%d", c.RedisHost, c.RedisPort)
}

func (c Config) RabbitMQURL() string {
	vhost := c.RabbitMQVHost
	if vhost == "" {
		vhost = "/"
	}
	return fmt.Sprintf("amqp://%s:%s@%s:%d%s", c.RabbitMQUser, c.RabbitMQPassword, c.RabbitMQHost, c.RabbitMQPort, vhost)
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getenvInt(key string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid integer for %s: %q", key, raw)
	}
	return value, nil
}

func getenvBool(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid boolean for %s: %q", key, raw)
	}
	return value, nil
}
