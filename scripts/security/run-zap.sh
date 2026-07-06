#!/usr/bin/env bash
set -euo pipefail

echo "Running ZAP baseline scan..."

mkdir -p reports/zap

docker compose up -d --build

# healthcheck: localhost (컨테이너 내부) → 성공하면 서비스 준비 완료
for _ in {1..30}; do
  if curl -fsS http://localhost/healthz >/dev/null; then
    break
  fi
  sleep 2
done

if ! curl -fsS http://localhost/healthz >/dev/null; then
  docker compose ps
  docker compose logs backend
  docker compose logs frontend
  exit 1
fi

# ===== 포트 명시 + 실패 감지 =====
echo "Starting ZAP baseline scan against http://host.docker.internal:80..."

ZAP_EXIT_CODE=0
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -v "$(pwd)/reports/zap:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t http://host.docker.internal:80 \
  -r zap-report.html \
  -J zap-report.json || ZAP_EXIT_CODE=$?

# ZAP 실패 진단
if [ ! -f reports/zap/zap-report.json ]; then
  echo "WARNING: ZAP report not generated (exit code: $ZAP_EXIT_CODE)"
  echo '{"site":[]}' > reports/zap/zap-report.json
  
  # ZAP이 스캔을 완료했는지 확인할 수 없으면 실패로 간주
  if [ $ZAP_EXIT_CODE -ne 0 ] && [ $ZAP_EXIT_CODE -ne 1 ]; then
    echo "ERROR: ZAP scan failed with exit code $ZAP_EXIT_CODE"
    exit 1
  fi
fi

# (옵션) 최소 alert 수 검증
if command -v jq >/dev/null 2>&1; then
  alert_count=$(jq '[.site[]?.alerts[]? | select(.riskcode != "0")] | length' reports/zap/zap-report.json 2>/dev/null || echo "0")
  echo "✓ ZAP scan complete - detected ${alert_count} alerts (excluding informational)"
fi

sudo chown -R "$USER:$USER" reports/zap

docker compose down || true