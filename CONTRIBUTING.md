# Contributing

Thanks for working on BugCode Shield. This is a local security scanner (Go API + worker + Next.js). Read [docs/README.md](docs/README.md) first.

## Before you write code

1. Run the stack: [docs/development-setup.md](docs/development-setup.md).
2. Confirm http://localhost:3000 and a scan of `testdata/vulnerable-sample` still work.
3. Match [docs/requirements-overview.md](docs/requirements-overview.md). Do not execute untrusted project code on the host. Do not give scanner containers the Docker socket.

## Repository map

```text
cmd/api                HTTP binary
cmd/worker             Scan binary
internal/server        Routes
internal/*             Domain + scanners + db
apps/web               Next.js
docker/                Dockerfiles
docs/                  Design and onboarding
testdata/              Safe-to-scan fixtures
scripts/               setup / start / stop / logs
```

Where to put a change: [Architecture — package map](docs/architecture.md#package-map-where-to-edit).

## Branch and pull requests

- Branch from the default branch. Name it after the change (`fix/trivy-skip-dirs`, `docs/data-flow`).
- Keep the PR small enough to review: one concern (UI, API, worker, docs).
- Description should say **why**, how to test, and any risk (migrations, Compose, secrets).
- Do not include `.env`, credentials, real GitHub/OpenAI tokens, or customer source.

Use GitHub (`gh`) for issues and PRs when this repo is on GitHub.

## Coding rules

**Go**

- Go 1.22+. `gofmt` on changed files.
- HTTP handlers stay thin; put SQL and rules in the domain package.
- New tables: add `internal/db/migrations/00N_name.sql`. Never edit an already-applied migration on a shared database; add a new file.
- Scanner flags and image tags live in `internal/scanning/runner.go`.
- Do not log secrets, GitHub tokens, or Authorization headers.

**Web**

- Next.js App Router under `apps/web/src/app`.
- Reuse `apps/web/src/components/ui.tsx` (Button `loading`, `LoadingScreen`, `InlineWait`).
- After UI changes that users can see, verify in the browser (not only a screenshot): click, submit, other routes that share the state.

**Compose**

- Ports stay on `127.0.0.1`.
- New environment variables: add to `.env.example` and `docker-compose.yml`, never commit `.env`.

## Tests

```bash
go test ./cmd/... ./internal/...
cd apps/web && npm run lint && npx tsc --noEmit
docker compose config >/dev/null
```

CI runs the same steps (`.github/workflows/ci.yml`). Add or update tests when you change parsers, path allowlists, or auth.

Manual check for scan-related work:

```bash
docker compose logs -f worker
```

Then run a scan from the UI and confirm logs then findings.

## Adding a scanner

1. Image + `docker run` args in `internal/scanning/runner.go` (`commandFor`).
2. Parser in `internal/scanning/normalize.go` producing `finding.Finding`.
3. Allow the name in `internal/scan` `allowedScanners` and the web checkbox list.
4. Skip caches (`node_modules`, `.pnpm-store`, `.git`, …).
5. Document it in `docs/scanner-integration.md`.
6. Do not run the tool on the host; keep `docker run` isolation.

## Adding an API endpoint

1. Method on the domain `Service`.
2. Register in `internal/server/server.go` (auth middleware unless it is public).
3. Wire construction in `cmd/api/main.go` if you add a new service.
4. Call it from `apps/web/src/lib/api.ts`.
5. Update `docs/api-documentation.md`.

## Security for contributors

- Treat `testdata/vulnerable-sample` as a **fixture**, not production code.
- Do not add exploit payloads, exploit PoCs, or attack runbooks to this repo.
- Redact secrets in findings and logs (Gitleaks path already allowlists and sanitizes).
- User-supplied tokens go through `internal/crypto`, never plaintext columns.

## Commits

- Write a short message that says why, not a file list.
- Only commit when asked if you are an automated agent in this workspace; humans: commit what belongs to the change, not `node_modules` or scan output under `data/`.

## Questions

If behavior is unclear, the source of truth is the running code plus:

- Scan job: `internal/worker/worker.go`
- HTTP surface: `internal/server/server.go`
- Scanner CLI: `internal/scanning/runner.go`
