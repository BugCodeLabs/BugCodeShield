#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Stops containers but keeps named volumes (database, queues, object storage).
docker compose down
echo "Containers stopped. Volumes were kept. Use 'docker compose down -v' only if you want to delete data."
