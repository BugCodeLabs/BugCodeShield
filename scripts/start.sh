#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo ".env is missing. Run ./scripts/setup.sh first."
  exit 1
fi

docker compose up -d
docker compose ps
echo
echo "Frontend:              http://localhost:3000"
echo "API live:              http://localhost:3001/health/live"
echo "API ready:             http://localhost:3001/health/ready"
echo "RabbitMQ management:   http://localhost:15672"
echo "MinIO console:         http://localhost:9001"
echo "SonarQube:             http://localhost:9002"
