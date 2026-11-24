# Security architecture

## Controls

- Secrets come from `.env`. `.env` is gitignored. `.env.example` has placeholders only.
- `setup.sh` generates random passwords when creating `.env`.
- Compose publishes ports on `127.0.0.1` only.
- `web` is on the `frontend` network. Data stores are on `backend` only. `api` spans both.
- Health JSON never includes connection strings or raw infrastructure errors.
- The **worker** mounts the host Docker socket so it can `docker run` scanners. **Scanner containers never receive that socket.**
- API and web images run as non-root. The worker must talk to Docker.
- GitHub and OpenAI tokens in Settings are AES-GCM ciphertext. The UI only shows a hint (`••••abcd`).
- Scanner logs are sanitized before they are stored for the dashboard.

## Risks deferred to later phases

| Risk | Phase | Planned control |
| --- | --- | --- |
| ZIP slip / path traversal | 3 | Canonicalize extract paths |
| Untrusted code execution | 4 | Never run uploads on the host |
| Docker socket in scanners | 4 | No socket in untrusted containers |
| Tenant source leakage | 2–4 | Authz + isolated object keys |
| Secret values in the UI | 8 | Redact findings and logs |
| Resource exhaustion | 3–4 | Size limits, timeouts, cgroup caps |

## Credentials in operator UIs

RabbitMQ, MinIO, and SonarQube consoles use the values in `.env`. Do not commit that file. Rotate local passwords by editing `.env` and recreating containers (`docker compose up -d --force-recreate rabbitmq minio`). Changing `SONARQUBE_ADMIN_PASSWORD` after the first start does not reset an existing SonarQube volume; remove `sonarqube_data` only if you intend to wipe that engine.
