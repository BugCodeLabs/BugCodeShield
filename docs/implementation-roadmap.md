# Implementation roadmap

| Phase | Status | Outcome |
| --- | --- | --- |
| 0 Architecture | Done | Go API, Next.js UI, Compose-first |
| 1 Docker + initial apps | Done | Healthy web, api, postgres, redis, rabbitmq, minio |
| 2 Application foundation | Done | Auth, orgs, projects, RBAC, migrations |
| 3 Source ingestion | Done | ZIP, folder upload, GitHub |
| 4 Scanning infrastructure | Done | Worker, statuses, isolated docker runner |
| 5 Semgrep | Done | JSON collection + normalization |
| 6 SonarQube | Done | Optional scanner + Compose `sonarqube` service |
| 7 Trivy | Done | Filesystem/dependency/config findings |
| 8 Gitleaks | Done | Redacted secret findings |
| 9 Unified dashboard | Done | Filters, history, JSON/SARIF export |
| 10 AI assistant | Done | Optional OpenAI-compatible explain |
| 11 Production readiness | Partial | Unit tests, CI workflow, Compose deploy |
