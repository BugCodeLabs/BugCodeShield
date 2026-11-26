# Architecture

BugCode Shield is a Go + Next.js application (Go module `bugcode-shield`, Compose project `bugcode-shield`). Two **binaries** share **domain packages**. Scanner tools are **not** Compose services; the worker pulls public images and runs them with `docker run`.

## Runtime processes

| Service | Image / entry | Role |
| --- | --- | --- |
| `web` | `apps/web` (Next.js 15) | Landing, auth UI, projects, scan dashboard. Proxies `/backend/*` to the API. |
| `api` | `cmd/api` | HTTP API, JWT, enqueue scan jobs, serve findings, scan WebSocket. |
| `worker` | `cmd/worker` | Consumes RabbitMQ, prepares source, starts scanner containers, writes findings. |
| `postgres` | Postgres 16 | System of record. |
| `redis` | Redis 7 | Live scan pub/sub (`bugcodeshield:scan-events`) plus health. |
| `rabbitmq` | RabbitMQ 3.13 | Scan job queue `bugcodeshield.scans`. |
| `minio` | MinIO | ZIP/object storage for uploaded archives. |
| `sonarqube` | SonarQube Community Build | Optional quality/SAST engine used by the `sonarqube` scanner. |

Scanner images (pulled on first use, not listed in Compose except the SonarQube server):

- `semgrep/semgrep:1.97.0`
- `aquasec/trivy:0.58.1`
- `zricethezav/gitleaks:v8.21.2`
- `sonarsource/sonar-scanner-cli:11` (optional; talks to the `sonarqube` service)
- `owasp/dependency-check:12.1.0` (optional)

## Why `cmd/` and `internal/` (not everything under `api/`)

This is standard Go layout.

```text
cmd/api/main.go       HTTP process only (listen, wire deps, exit)
cmd/worker/main.go    Scan process only (consume queue, docker run)
internal/server       Chi routes — the HTTP surface
internal/auth|org|project|source|scan|finding|ai|settings
                      Domain logic used by API and/or worker
internal/scanning     docker run + JSON parsers
internal/live         Redis pub/sub hub for scan WebSockets
internal/queue|db|config|platform|crypto|health
                      Infrastructure
apps/web              Next.js UI
```

The worker **must** import `internal/source`, `internal/scanning`, and `internal/finding`. Another `main` cannot import `cmd/api`. Putting scanner and crypto code only inside `internal/server` would mix HTTP with Docker jobs.

A top-level Go folder named `api/` usually means OpenAPI/protobuf specs, not handlers. Product HTTP lives in `internal/server` under `/api/v1`.

## Networks

- `frontend`: `web`, `api`. The browser never talks to Postgres, Redis, RabbitMQ AMQP, or MinIO S3.
- `backend`: `api`, `worker`, and data stores.
- `scanners`: `worker`, `sonarqube`, and ephemeral scanner containers. No Postgres/Redis/MinIO.

`api` sits on both networks. Containers resolve each other by Compose service name. `localhost` inside a container is that container.

Worker mounts:

- Host Docker socket (to start scanner containers)
- `data/scans`, `data/cache`, `data/sources`
- For local folder scans, the API/worker resolve a host path; the **scanner** container gets `-v hostPath:/src:ro`

## Package map (where to edit)

| Change | Start here |
| --- | --- |
| New HTTP route | `internal/server/server.go` + the domain `Service` |
| Login / JWT / profile | `internal/auth` |
| GitHub / ZIP / local folder | `internal/source` |
| Skip generated dirs during scan | `internal/source/skip.go` |
| Enqueue or scan status | `internal/scan` |
| Live scan WebSocket | `internal/scan/ws.go`, `internal/live` |
| Semgrep/Trivy/Gitleaks/SonarQube CLI flags | `internal/scanning/runner.go` |
| Finding JSON shape | `internal/scanning/normalize.go` |
| AI explain | `internal/ai` + user keys in `internal/settings` |
| Web pages | `apps/web/src/app` |
| Compose / ports | `docker-compose.yml`, `.env.example` |
| Schema | `internal/db/migrations/*.sql` (runs on API/worker boot) |

## Auth and tenancy

- Register creates a user and a default organization (`owner`).
- JWT in `Authorization: Bearer`. Scan WebSocket uses the same JWT as `?token=` on `GET /api/v1/scans/{id}/ws` (browser cannot set headers on `WebSocket`). Connect to the API port; Next.js `/backend` is fetch-only.
- Project access goes through `organization_members`.
- User settings (GitHub token, OpenAI key) are per user, encrypted.

## Scan isolation

Each selected scanner is `docker run --rm` with:

- Read-only `/src`
- Writable `/out` for JSON reports
- Memory / CPU / PID limits
- `--cap-drop ALL` and `no-new-privileges`
- No Docker socket

The worker reads `semgrep.json` / `trivy.json` / `gitleaks.json` / `sonarqube.json`, parses them, and inserts `findings` with a category (`security_hotspot`, `vulnerability`, `infrastructure`, `secret_leak`, `duplication`, `code_quality`). One scanner failing does not cancel the others. Semgrep, Trivy, Gitleaks, and Dependency-Check run at the same time (separate `/out/{scanner}` dirs). SonarQube starts after that wave so the 5 GB scanner does not overlap the CLIs.

## Desktop

Out of scope. Do not add `cmd/desktop` unless requested.
