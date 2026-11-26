# Database design

PostgreSQL is the system of record. Migrations live in `internal/db/migrations` and run on API/worker startup.

Core tables:

- `users` — accounts with bcrypt password hashes
- `organizations` / `organization_members` — tenants and RBAC (`owner`, `admin`, `member`, `viewer`)
- `projects` — belong to an organization
- `project_sources` — ZIP / files / GitHub / local; `local_path` for in-place scans; GitHub tokens as AES-GCM ciphertext
- `scans` — lifecycle `QUEUED` → `PREPARING` → `RUNNING` → `COMPLETED` / `FAILED` / `CANCELLED`
- `findings` — normalized scanner results, unique per `(scan_id, fingerprint)`; `category` groups hotspot / vulnerability / infrastructure / secret leak / duplication / code quality
- `scan_logs` — operator-visible progress
- `user_settings` — encrypted GitHub token and OpenAI key, plus optional model / base URL

Migrations: `001_init.sql`, `002_local_path.sql`, `003_user_settings.sql`, `004_finding_category.sql`, `005_scan_source_cascade.sql`. Applied automatically on API and worker startup. Deleting a project removes its sources, scans, findings, and logs.
