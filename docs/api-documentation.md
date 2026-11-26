# API documentation

Base path: `/api/v1`. The web app calls these as `/backend/api/v1/...`.

All product routes need `Authorization: Bearer <jwt>` except **register**, **login**, **health**, and the scan WebSocket (JWT as `?token=` because browsers cannot set `Authorization` on `WebSocket`).

Health (no `/api/v1` prefix): `GET /health/live`, `GET /health`, `GET /health/ready`.

## Auth

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/v1/auth/register` | `{email, name, password}` → `{token, user}` + default org |
| POST | `/api/v1/auth/login` | `{email, password}` → `{token, user}` |
| GET | `/api/v1/auth/me` | Current user |
| PATCH | `/api/v1/auth/me` | `{name}` |

## Settings (encrypted credentials)

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/settings` | Flags + hints only (`github_token_set`, `openai_api_key_hint`, …) |
| PUT | `/api/v1/settings` | `{github_token?, openai_api_key?, openai_base_url?, openai_model?, clear_github_token?, clear_openai_api_key?}` |

Empty token fields mean “keep existing”. Never returns the full secret.

## Organizations and projects

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/orgs` | Memberships |
| POST | `/api/v1/orgs` | `{name}` |
| GET | `/api/v1/orgs/{orgID}/projects` | Projects in an org |
| POST | `/api/v1/orgs/{orgID}/projects` | `{name, description}` |
| GET | `/api/v1/projects` | Projects the user can access |
| GET | `/api/v1/projects/{projectID}` | Detail |
| GET | `/api/v1/projects/{projectID}/summary` | Finding summary |

## Sources

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/projects/{projectID}/sources` | Source versions |
| POST | `/api/v1/projects/{projectID}/sources/zip` | Multipart `file` |
| POST | `/api/v1/projects/{projectID}/sources/files` | Multipart files + paths |
| POST | `/api/v1/projects/{projectID}/sources/local` | `{path}` or `{name, children}` — scan in place |
| POST | `/api/v1/projects/{projectID}/sources/github` | `{repository, ref, token}` — token optional if saved in Settings |

Local connect may respond with `status: "choose"` and `matches` when several folders share a name.

## Scans and findings

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/v1/projects/{projectID}/scans` | `{source_id, scanners}` → `202` + scan (`QUEUED`) |
| GET | `/api/v1/projects/{projectID}/scans` | History |
| GET | `/api/v1/scans/{scanID}` | Status, source label, finding_count |
| GET | `/api/v1/scans/{scanID}/ws` | WebSocket live status + logs (`?token=<jwt>`). Connect to the API host (`:3001`), not `/backend`. |
| POST | `/api/v1/scans/{scanID}/cancel` | Cancel if still running |
| GET | `/api/v1/scans/{scanID}/logs` | Scanner logs (REST fallback) |
| GET | `/api/v1/scans/{scanID}/findings` | Filters: `severity`, `scanner`, `category`, `file`, `q`. Categories: `security_hotspot`, `vulnerability`, `infrastructure`, `secret_leak`, `duplication`, `code_quality` |
| GET | `/api/v1/scans/{scanID}/export.json` | JSON export |
| GET | `/api/v1/scans/{scanID}/export.sarif` | SARIF export |
| POST | `/api/v1/findings/{findingID}/explain` | AI text; needs OpenAI key in Settings or env |

Allowed `scanners` values: `semgrep`, `trivy`, `gitleaks`, `sonarqube`, `dependency-check`. Default if omitted: the first three.

Errors are `{ "error": "...", "code": "..." }` (`validation`, `unauthorized`, `ai_disabled`, …).
