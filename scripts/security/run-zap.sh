#!/usr/bin/env bash
set -euo pipefail

echo "Running ZAP authenticated scan..."

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
  docker compose logs backend
  docker compose logs frontend
  exit 1
fi

# ===== 시드 데이터 생성 =====
# BootstrapRunner는 admin(super_admin)만 생성하므로 스캔용 customer·tenant를 직접 생성한다
echo "Creating scan seed data..."

ADMIN_TOKEN=$(curl -sf -X POST http://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASSWORD}\"}" \
  | jq -r '.data.accessToken')

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
  echo "ERROR: Admin login failed"
  exit 1
fi

TENANT_ID=$(curl -sf -X POST http://localhost/api/v1/tenants \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -d '{"name":"ZAP Scan Shop","slug":"zap-scan","description":"DAST scan test tenant"}' \
  | jq -r '.data.id')

# 런타임에만 존재하는 임시 계정이므로 매 실행마다 무작위 비밀번호를 생성한다
# tr|head 조합은 pipefail 환경에서 SIGPIPE를 유발하므로 openssl을 사용한다
CUSTOMER_PASS=$(openssl rand -hex 12)

curl -sf -X POST http://localhost/api/v1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -d "{\"username\":\"zap-customer\",\"password\":\"${CUSTOMER_PASS}\",\"role\":\"customer\",\"displayName\":\"ZAP Test Customer\",\"tenantId\":\"${TENANT_ID}\"}" \
  > /dev/null

CUSTOMER_TOKEN=$(curl -sf -X POST http://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"zap-customer\",\"password\":\"${CUSTOMER_PASS}\"}" \
  | jq -r '.data.accessToken')

if [ -z "$CUSTOMER_TOKEN" ] || [ "$CUSTOMER_TOKEN" = "null" ]; then
  echo "ERROR: Customer login failed"
  exit 1
fi

# ===== ZAP Automation Framework 실행 =====
echo "Starting ZAP authenticated scan against http://host.docker.internal..."

ZAP_EXIT_CODE=0
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -e ZAP_CUSTOMER_TOKEN="${CUSTOMER_TOKEN}" \
  -v "$(pwd)/reports/zap:/zap/wrk" \
  -v "$(pwd)/scripts/security:/zap/config:ro" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/config/automation.yaml || ZAP_EXIT_CODE=$?

if [ ! -f reports/zap/zap-report.json ]; then
  echo "WARNING: ZAP report not generated (exit code: $ZAP_EXIT_CODE)"
  echo '{"site":[]}' > reports/zap/zap-report.json
fi

if command -v jq >/dev/null 2>&1; then
  alert_count=$(jq '[.site[]?.alerts[]? | select(.riskcode != "0")] | length' reports/zap/zap-report.json 2>/dev/null || echo "0")
  echo "ZAP scan complete — ${alert_count} alerts detected (excluding informational)"
fi

sudo chown -R "$USER:$USER" reports/zap

docker compose down || true