# Docker guide

Phase 1 is designed to start with:

```bash
docker compose up -d
```

## What each service does

| Service | Image / build | Host URL | Internal DNS |
| --- | --- | --- | --- |
| `web` | `apps/web/Dockerfile` | http://localhost:3000 | `web:3000` |
| `api` | `docker/api.Dockerfile` | http://localhost:3001 | `api:3000` |
| `postgres` | `postgres:16-alpine` | localhost:5432 | `postgres:5432` |
| `redis` | `redis:7-alpine` | localhost:6379 | `redis:6379` |
| `rabbitmq` | `rabbitmq:3.13-management-alpine` | http://localhost:15672 | `rabbitmq:5672` AMQP |
| `minio` | `bitnamilegacy/minio` (digest-pinned) | http://localhost:9001 console, localhost:9000 S3 | `minio:9000` S3 |
| `sonarqube` | `sonarqube:26.11.0.134175-community` | http://localhost:9002 | `sonarqube:9000` |

Host ports bind to `127.0.0.1` so admin interfaces are not published on your LAN.

MinIO uses `bitnamilegacy/minio` because the official `minio/minio` image was denied by the registry used on this machine. The API still talks S3 to `minio:9000`. The data volume is `/bitnami/minio/data`.

## Volumes

Named volumes survive `docker compose down`:

- `postgres_data`
- `redis_data`
- `rabbitmq_data`
- `minio_data`
- `sonarqube_data`, `sonarqube_extensions`, `sonarqube_logs`

## Commands

```bash
docker compose up -d          # create and start
docker compose ps             # status
docker compose logs -f        # all logs
docker compose logs -f api    # one service
docker compose down           # stop; keep volumes
docker compose down -v        # stop AND delete volumes
```

`docker compose down -v` destroys application data. There is no undo.

Equivalent scripts: `scripts/start.sh`, `scripts/stop.sh`, `scripts/logs.sh`, `scripts/status.sh`.

## Health checks and startup order

Compose waits for `service_healthy`, not merely `started`.

1. postgres, redis, rabbitmq, minio become healthy.
2. `api` starts and `/health/live` must succeed.
3. `web` starts after `api` is healthy.

If a container is `unhealthy`, inspect it:

```bash
docker compose ps
docker compose logs --tail=100 SERVICE
docker inspect --format='{{json .State.Health}}' bugcode-shield-SERVICE-1
```

## How the frontend reaches the API

The browser calls `http://localhost:3000/backend/health/ready`. Next.js (inside the `web` container) proxies that to `http://api:3000/health/ready`. That is why the UI does not use `localhost` for the API: `localhost` from inside `web` would mean the frontend container itself.

## Debugging connectivity

```bash
docker compose exec postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"
docker compose exec redis redis-cli ping
docker compose exec api wget -qO- http://127.0.0.1:3000/health/ready
```

Load `.env` first if you need the username, or pass the values from that file.
