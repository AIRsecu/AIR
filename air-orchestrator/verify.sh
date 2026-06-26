#!/usr/bin/env bash
# AIR 패치 검증: 패치된 워킹트리로 throwaway 백엔드 빌드 →
#   런타임 방어/탐지 모두 OFF → 공격 재현 → '소스 자체로' 차단되면 통과(exit 0).
# 사용: verify.sh <repo_dir> <scenario> <admin_user> <admin_pass>
set -u
REPO="$1"; SCENARIO="$2"; AU="$3"; AP="$4"
BASE="http://localhost:8082"
PROJ="airverify"
COMPOSE="docker-compose -p $PROJ -f docker-compose.verify.yml"

cd "$REPO" || { echo "[verify] repo 경로 오류"; exit 2; }
[ -f .env ] || { echo "[verify] .env 없음(JWT 시크릿/ADMIN 필요)"; exit 2; }

cleanup() { (cd "$REPO" && $COMPOSE down -v >/dev/null 2>&1); }
trap cleanup EXIT

echo "[verify] 빌드+기동(패치된 소스 컴파일 검증 포함)…"
if ! $COMPOSE up -d --build >/tmp/airverify_build.log 2>&1; then
  echo "[verify] 빌드/기동 실패(컴파일 오류 가능) → 검증 실패"; tail -5 /tmp/airverify_build.log; exit 1
fi

echo "[verify] 헬스 대기…"
for i in $(seq 1 18); do
  curl -sf "$BASE/api/v1/health" >/dev/null 2>&1 && break
  sleep 5
  [ "$i" = 18 ] && { echo "[verify] 헬스 타임아웃 → 검증 실패"; docker logs airverify-backend 2>&1 | tail -8; exit 1; }
done

TOKEN=$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$AU\",\"password\":\"$AP\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['accessToken'])" 2>/dev/null)
[ -n "$TOKEN" ] || { echo "[verify] 로그인 실패 → 검증 실패"; exit 1; }
AUTH="Authorization: Bearer $TOKEN"

# 런타임 가드/탐지 모두 OFF → 오직 소스 패치만이 공격을 막을 수 있음
curl -s -X POST "$BASE/api/v1/air/defenses/order.qty-guard/disable" -H "$AUTH" >/dev/null
curl -s -X POST "$BASE/api/v1/air/defenses/air.detection/disable"    -H "$AUTH" >/dev/null
echo "[verify] 방어상태: $(curl -s $BASE/api/v1/air/defenses -H "$AUTH")"

echo "[verify] 공격 재현($SCENARIO)…"
python3 air-attack/attack.py --base "$BASE" --admin-user "$AU" --admin-pass "$AP" "$SCENARIO"
RC=$?   # attack.py: 1=VULNERABLE(취약), 0=DEFENDED(차단)
if [ $RC -eq 0 ]; then
  echo "[verify] ✓ 소스 패치만으로 공격 차단됨 → 통과"; exit 0
else
  echo "[verify] ✗ 패치 후에도 공격 성공 → 실패"; exit 1
fi
