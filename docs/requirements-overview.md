# Requirements overview

BugCode Shield is a **local web app** that runs several security scanners against one project and shows a single issues dashboard.

This document is the product contract for new contributors. If a change fights these rules, it does not belong in the default path.

## Goals

- One account, one workspace, many projects.
- Point a project at **one location**: a folder on this computer, a ZIP, or a GitHub repository.
- Run **Semgrep** (code issues), **Trivy** (CVEs / misconfig / secrets), **Gitleaks** (secrets), and optionally **SonarQube** and **OWASP Dependency-Check**.
- Show **live scanner logs**, then a unified finding list (severity, file, line, snippet, export).
- Keep untrusted project code **off the host as a process**. Scanners run in isolated Docker containers with a read-only mount.

## In scope

| Area | Requirement |
| --- | --- |
| UI | Next.js web app only. No desktop shell unless explicitly requested. |
| Auth | Email/password, JWT, per-user settings (GitHub token, OpenAI key). |
| Sources | Local folder (scan in place), ZIP extract-to-disk or upload, GitHub clone. |
| Scans | Async jobs via RabbitMQ. Status `QUEUED` → `PREPARING` → `RUNNING` → `COMPLETED` / `FAILED` / `CANCELLED`. |
| Findings | Normalized model, JSON + SARIF export, optional AI explain (never auto-applies code). |
| Ops | Docker Compose for local and default deploy. Postgres is the system of record. |

## Out of scope (unless requested)

- Running uploaded code on the host (`node`, `go test`, install hooks, etc.).
- Executing scanner tools as host binaries instead of Docker images.
- Multi-cloud SaaS tenancy, billing, or public internet exposure of Postgres/Redis/RabbitMQ/MinIO.
- Applying AI patches automatically.

## Constraints that must hold

1. **No full-codebase upload for a local folder.** Bind-mount the host path read-only into the scanner container.
2. **Scanner containers never receive `docker.sock`.** Only the worker mounts the socket.
3. **Secrets are encrypted at rest** (`ENCRYPTION_KEY`, AES-GCM). The UI never shows full GitHub/OpenAI tokens after save.
4. **Compose ports bind to `127.0.0.1`.** Do not publish data stores on `0.0.0.0`.
5. **`.env` is not committed.** `.env.example` has placeholders only.
6. Local paths must stay under the configured home allowlist (`SCAN_HOST_HOME`).

## Personas

- **Developer using BugCode Shield:** registers, adds a project, starts a scan, triages issues. Step-by-step: [user-guide.md](./user-guide.md).
- **Contributor to this repo:** extends API, UI, worker, or scanners without breaking the constraints above.

## Success for a first scan

A new user can:

1. Open http://localhost:3000 and create an account.
2. Create a project and attach `testdata/vulnerable-sample` (ZIP or folder).
3. Start Semgrep + Trivy + Gitleaks.
4. Watch logs, then see findings with file and line.
5. Export JSON/SARIF.

If that path breaks, the change is not ready.
