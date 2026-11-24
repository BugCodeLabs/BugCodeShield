# Development setup

## Prerequisites

- Docker Engine 24+
- Docker Compose v2
- Optional for native runs: Go 1.22+, Node.js 20+, npm

## First run

```bash
./scripts/setup.sh
./scripts/start.sh
./scripts/status.sh
```

`setup.sh` copies `.env.example` to `.env` if needed and replaces placeholder passwords with random values. Edit `.env` before starting if you want known local credentials.

## Native API (optional)

The API can run on the host while infrastructure stays in Docker:

```bash
docker compose up -d postgres redis rabbitmq minio
export $(grep -v '^#' .env | xargs)
go run ./cmd/api
```

Keep `POSTGRES_HOST=localhost` (the `.env.example` default) for this mode. Compose overrides those hosts to service names for the `api` container.

## Native web (optional)

```bash
cd apps/web
npm install
API_INTERNAL_URL=http://localhost:3001 npm run dev
```

The Next.js app proxies `/backend/*` to `API_INTERNAL_URL`.

## Checks

```bash
go test ./cmd/... ./internal/...
cd apps/web && npm run lint && npx tsc --noEmit
```

After a UI change, open the app in a browser and exercise the flow (not only a screenshot).

## Next reading

[docs/README.md](./README.md) · [User guide](./user-guide.md) · [Contributing](../CONTRIBUTING.md) · [Data flow](./data-flow.md)
