# Data flow

How data moves for a developer joining the project. Sequence is what you will see in the UI and in `docker compose logs -f api worker`.

## System context

```mermaid
flowchart LR
  Browser[Browser]
  Web[Next.js web :3000]
  API[Go API :3001]
  PG[(Postgres)]
  Q[[RabbitMQ]]
  Redis[(Redis)]
  Minio[(MinIO)]
  Worker[Go worker]
  Docker[Host Docker]
  Scanners[Semgrep / Trivy / Gitleaks / SonarQube]

  Browser --> Web
  Web -->|"/backend/*"| API
  Browser -->|"scan WebSocket :3001"| API
  API --> PG
  API --> Q
  API --> Redis
  API --> Minio
  Q --> Worker
  Worker --> PG
  Worker --> Redis
  Worker --> Minio
  Worker --> Docker
  Docker --> Scanners
```

The browser only reaches `web`. `web` rewrites `/backend/api/v1/...` to the API. Data stores are not published for the browser.

## Authenticated request

```mermaid
sequenceDiagram
  participant B as Browser
  participant W as web
  participant A as api
  participant P as Postgres

  B->>W: GET /app/projects/:id
  W->>A: GET /backend/api/v1/projects/:id<br/>Authorization Bearer JWT
  A->>A: auth.Middleware (parse JWT)
  A->>P: org membership + project
  P-->>A: row
  A-->>W: JSON
  W-->>B: page
```

JWT is created on register/login and stored in `localStorage` (`bugcodeshield_token`). Send it on every product API call.

## Add source

Three kinds. All produce a `project_sources` row the scan will use.

```mermaid
flowchart TD
  Start[User picks source type]
  Start --> Zip[ZIP]
  Start --> Dir[Folder on this computer]
  Start --> GH[GitHub]

  Zip --> Z1[POST /sources/zip or extract to data/sources]
  Z1 --> Row[project_sources]

  Dir --> D1[POST /sources/local path or name+children]
  D1 --> D2[Resolve under SCAN_HOST_HOME]
  D2 --> Row

  GH --> G1[POST /sources/github]
  G1 --> G2[Verify repo via GitHub API]
  G2 --> G3[Encrypt token if present]
  G3 --> Row
```

- **Local folder:** no full tree upload. The API stores the **host path**. The scanner later mounts that path as `/src:ro`.
- **GitHub:** token may come from the request or from **Settings** (`user_settings`). Clone happens in the worker, not in the browser.
- **ZIP:** stored in MinIO or extracted under `data/sources/{id}/src`.

## Scan pipeline

```mermaid
sequenceDiagram
  participant U as UI
  participant A as api
  participant P as Postgres
  participant Q as RabbitMQ
  participant R as Redis
  participant W as worker
  participant D as docker run
  participant S as scanner image

  U->>A: POST /projects/:id/scans {source_id, scanners}
  A->>P: INSERT scans status=QUEUED
  A->>Q: publish {scan_id}
  A-->>U: 202 Scan
  U->>A: WebSocket GET /scans/:id/ws?token=JWT

  Q->>W: consume
  W->>P: PREPARING
  W->>R: publish scan event
  A-->>U: status + logs
  W->>W: materialize source<br/>in-place path / unzip / git clone
  W->>P: RUNNING

  par CLI scanners
    W->>D: docker run semgrep/trivy/gitleaks/…
    D->>S: write /out/{scanner}/*.json
    W->>P: INSERT findings + scan_logs
  end
  W->>D: docker run sonar-scanner (after CLIs)
  D->>S: SonarQube analysis
  W->>P: INSERT findings
  W->>R: publish log/status
  A-->>U: log + finding_count

  W->>P: COMPLETED or FAILED
  A-->>U: done
  U->>A: GET /scans/:id/findings
```

The scan page opens a WebSocket to the API host (`ws://127.0.0.1:3001`). RabbitMQ stays the job queue; Redis fans worker log/status events out to API sockets. REST `GET /scans/:id` polling is only a fallback if the socket cannot connect.

Worker materialize rules (`internal/worker/worker.go`):

| `project_sources.kind` | What the worker does | `hostSrc` for Docker |
| --- | --- | --- |
| `local` (or zip with `local_path`) | Scan in place | the stored host path |
| `zip` / `files` without local path | Download from MinIO, extract to `data/scans/{id}/src` | that workspace |
| `github` | `git clone --depth 1` into workspace | that workspace |

## Finding ingest

```mermaid
flowchart LR
  JSON[Scanner JSON in /out]
  Parse[ParseSemgrep / ParseTrivy / ParseGitleaks / ParseSonarQube]
  Model[finding.Finding]
  DB[(findings table)]
  UI[Issues page]

  JSON --> Parse --> Model --> DB --> UI
```

Parsers live in `internal/scanning/normalize.go`. Fingerprint uniqueness is `(scan_id, fingerprint)`.

## Settings and AI

```mermaid
flowchart LR
  Settings[PUT /settings]
  Enc[AES-GCM ENCRYPTION_KEY]
  US[(user_settings)]
  Explain[POST /findings/:id/explain]
  OpenAI[OpenAI-compatible API]

  Settings --> Enc --> US
  Explain --> US
  Explain --> OpenAI
```

Ask AI uses the user's saved OpenAI key first, then `OPENAI_API_KEY` from the environment. No key → `ai_disabled` and the UI points at Settings. The model must not apply code changes.

## Where logs go

| You see | Stored as |
| --- | --- |
| UI scanner log panel | `scan_logs` rows (`scanner`, `level`, `message`) |
| `docker compose logs worker` | worker slog (job received, clone failed, …) |
| `docker compose logs api` | HTTP access log |

When debugging a failed Trivy/Semgrep run, read **both** the UI log and worker logs. The UI text is sanitized (tokens stripped, truncated).
