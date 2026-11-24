#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

docker compose ps
echo

if command -v curl >/dev/null 2>&1; then
  echo "API live:"
  curl -sS "http://127.0.0.1:${API_PORT:-3001}/health/live" || true
  echo
  echo "API ready:"
  curl -sS "http://127.0.0.1:${API_PORT:-3001}/health/ready" || true
  echo
else
  echo "Install curl to query health endpoints from this script."
fi
