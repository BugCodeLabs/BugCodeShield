#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker Engine and retry."
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required (docker compose)."
  exit 1
fi

if [[ ! -f .env ]]; then
  cp .env.example .env
  gen() { openssl rand -hex 16; }
  sed -i "s/change-me-postgres/$(gen)/" .env
  sed -i "s/change-me-redis/$(gen)/" .env
  sed -i "s/change-me-rabbitmq/$(gen)/" .env
  sed -i "s/change-me-minio-password/$(gen)/" .env
  echo "Created .env with generated passwords."
else
  echo ".env already exists; leaving existing secrets unchanged."
fi

ensure_env() {
  local key="$1"
  local value="$2"
  if ! grep -q "^${key}=" .env; then
    echo "${key}=${value}" >> .env
    echo "Added ${key} to .env"
  fi
}
ensure_env JWT_SECRET "$(openssl rand -hex 32)"
ensure_env ENCRYPTION_KEY "$(openssl rand -hex 32)"
ensure_env SONARQUBE_ADMIN_PASSWORD "Bcs-$(openssl rand -hex 12)!9A"
mkdir -p data/scans data/cache data/sources
chmod 777 data/scans data/cache data/sources || true

echo "Pulling images and building application services..."
docker compose pull
docker compose build
echo "Pulling scanner images (used by the worker)..."
docker pull semgrep/semgrep:1.97.0 || true
docker pull aquasec/trivy:0.58.1 || true
docker pull zricethezav/gitleaks:v8.21.2 || true
docker pull sonarsource/sonar-scanner-cli:11 || true
docker pull sonarqube:26.11.0.134175-community || true

echo
echo "Setup complete. Next:"
echo "  ./scripts/start.sh"
echo "  or: docker compose up -d"
