# BugCode Shield

Unified code security and quality analysis platform.

Register an account, create a project, upload source (ZIP, folder, or GitHub), and run Semgrep, Trivy, Gitleaks, and optionally SonarQube and OWASP Dependency-Check. Findings land in one dashboard with JSON/SARIF export and an optional AI explanation.

## Quick start

```bash
./scripts/setup.sh
./scripts/start.sh
```

Open http://localhost:3000, create an account, then scan `testdata/vulnerable-sample` as a ZIP or folder.

New users: [How to scan your project](http://localhost:3000/guide) · [docs/user-guide.md](docs/user-guide.md)

## Services

| Service | URL |
| --- | --- |
| Web | http://localhost:3000 |
| API ready | http://localhost:3001/health/ready |
| RabbitMQ | http://localhost:15672 |
| MinIO | http://localhost:9001 |
| SonarQube | http://localhost:9002 |

Credentials for operator UIs are in `.env`.

```bash
docker compose up -d
docker compose ps
docker compose logs -f worker
docker compose down          # keep data
docker compose down -v       # DELETE data
```

## Scan flow

1. API stores source in MinIO and enqueues a RabbitMQ job.
2. The worker prepares an isolated workspace.
3. Scanners run in separate Docker containers: no privileges, dropped capabilities, read-only source, no access to Postgres/Redis/MinIO.
4. Reports are normalized into a common finding model.

The worker mounts the host Docker socket. Scanner containers never receive that socket.

Set `OPENAI_API_KEY` or save a key in **Settings** if you want Ask AI. It explains findings only; it never writes your code.

## Documentation

New contributors: start at [`docs/README.md`](docs/README.md) (architecture, requirements, data flow, contributing). End users: [`docs/user-guide.md`](docs/user-guide.md).
