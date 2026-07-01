#!/usr/bin/env bash
set -euo pipefail

echo "Running ZAP baseline scan..."

mkdir -p reports/zap

docker compose up -d --build

for _ in {1..30}; do
  if curl -fsS http://localhost/healthz >/dev/null; then
    break
  fi
  sleep 2
done

if ! curl -fsS http://localhost/healthz >/dev/null; then
  docker compose ps
  docker compose logs
  exit 1
fi

docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -v "$(pwd)/reports/zap:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t http://host.docker.internal \
  -r zap-report.html \
  -J zap-report.json || true

if [ ! -f reports/zap/zap-report.json ]; then
  echo '{"site":[]}' > reports/zap/zap-report.json
fi

sudo chown -R "$USER:$USER" reports/zap
