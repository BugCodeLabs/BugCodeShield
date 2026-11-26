# Scanner integration

Enabled by default: Semgrep, Trivy, Gitleaks. Optional: SonarQube, OWASP Dependency-Check.

The worker starts each scanner with `docker run`:

- Read-only source mount
- Memory, CPU, and PID limits
- Capabilities dropped
- `no-new-privileges`
- Dedicated `scanners` network (egress for rule/CVE databases, no Postgres/MinIO/Redis)
- Trivy stores its vulnerability DB in `data/cache` on the host so scans are not limited by tmpfs size
- Generated trees are excluded for **every language** this product scans, not only Node.js. The list lives in `internal/source/skip.go` (`node_modules`, `vendor`, `target`, `.venv`, `dist`, `.git`, `.nx`, `.next`, `.turbo`, `.cache`, `coverage`, `bin`/`obj`, …). ZIP extract, file counts, Semgrep/Trivy/Gitleaks/SonarQube/Dependency-Check flags, and empty Docker overlays on those folders all use that list so scanners never read dependency or build output.

Scanner containers never receive the Docker socket. GitHub tokens are used only for `git clone` in the worker and are not passed into scanner environment variables. Gitleaks secrets are redacted before they reach the dashboard.

## SonarQube

Unlike the CLI-only tools, SonarQube needs a server. Compose starts `sonarqube` on the `scanners` network (host UI: http://localhost:9002). The worker:

1. Waits until `/api/system/status` is `UP` (first boot can take a few minutes).
2. Sets the admin password from `SONARQUBE_ADMIN_PASSWORD` if the instance still has `admin`/`admin`.
3. Runs `sonarsource/sonar-scanner-cli` with a per-scan project key.
4. Waits for the compute-engine task, then pulls issues and security hotspots into the common finding model.

Tick **SonarQube** on the project page; it is not selected by default. The scanner container gets 5 GB RAM so JS/TS analysis of large repos does not die on the Node heap. The server JVM is about 2.5 GB. First boot and large projects can take several minutes. If the service is still starting, that scanner fails and the others still complete.

Test fixture: `testdata/vulnerable-sample` (unsafe-by-design demo app, not for deployment).
