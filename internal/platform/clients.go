package platform

import (
	"context"
	"fmt"
	"time"

	"bugcode-shield/internal/config"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/redis/go-redis/v9"
)

type Clients struct {
	Postgres *pgxpool.Pool
	Redis    *redis.Client
	MinIO    *minio.Client
	cfg      config.Config
}

func New(cfg config.Config) (*Clients, error) {
	pool, err := pgxpool.New(context.Background(), cfg.PostgresDSN())
	if err != nil {
		return nil, fmt.Errorf("postgres pool: %w", err)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr(),
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	mc, err := minio.New(cfg.MinIOEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinIOAccessKey, cfg.MinIOSecretKey, ""),
		Secure: cfg.MinIOUseSSL,
	})
	if err != nil {
		pool.Close()
		_ = rdb.Close()
		return nil, fmt.Errorf("minio client: %w", err)
	}

	return &Clients{
		Postgres: pool,
		Redis:    rdb,
		MinIO:    mc,
		cfg:      cfg,
	}, nil
}

func (c *Clients) Close() {
	if c.Postgres != nil {
		c.Postgres.Close()
	}
	if c.Redis != nil {
		_ = c.Redis.Close()
	}
}

func (c *Clients) PingPostgres(ctx context.Context) error {
	return c.Postgres.Ping(ctx)
}

func (c *Clients) PingRedis(ctx context.Context) error {
	return c.Redis.Ping(ctx).Err()
}

func (c *Clients) PingRabbitMQ(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	timeout := 2 * time.Second
	if ok {
		timeout = time.Until(deadline)
		if timeout <= 0 {
			return ctx.Err()
		}
	}

	conn, err := amqp.DialConfig(c.cfg.RabbitMQURL(), amqp.Config{
		Dial: amqp.DefaultDial(timeout),
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	return ch.Close()
}

func (c *Clients) PingMinIO(ctx context.Context) error {
	_, err := c.MinIO.ListBuckets(ctx)
	return err
}

func (c *Clients) Config() config.Config {
	return c.cfg
}
