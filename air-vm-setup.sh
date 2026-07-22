#!/usr/bin/env bash
# ============================================================
#  AIR 방어 E2E — Ubuntu VM 프로비저닝 (VMware/Ubuntu 24.04 데스크톱)
#  이 스크립트를 VM 안으로 복사한 뒤 실행:
#     bash air-vm-setup.sh
#  하는 일: Docker · Ollama(로컬 LLM) 설치 → 모델 pull → AIR 클론
#           → .env 생성 → 방어 lab 스택 기동
#  (llm_patcher 로컬 LLM 분기는 feature/air-defense 소스에 포함 — 별도 패치 불필요)
# ============================================================
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/AIRsecu/AIR.git}"
BRANCH="${BRANCH:-feature/air-defense}"
WORK="${WORK:-$HOME/air-lab}"
MODEL="${MODEL:-qwen2.5-coder:7b}"

echo "== [1/6] 패키지 설치 (Docker · git · python3) =="
sudo apt-get update -y
sudo apt-get install -y docker.io docker-buildx docker-compose-v2 git python3 curl openssl
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER" || true   # 그룹 반영은 재로그인 후. 본 스크립트는 sudo docker 사용.

# verify.sh 가 v1 'docker-compose' 를 호출하므로 v2 로 넘기는 셔임 설치
if ! command -v docker-compose >/dev/null 2>&1; then
  echo '#!/usr/bin/env bash' | sudo tee /usr/local/bin/docker-compose >/dev/null
  echo 'exec docker compose "$@"' | sudo tee -a /usr/local/bin/docker-compose >/dev/null
  sudo chmod +x /usr/local/bin/docker-compose
  echo "[shim] docker-compose → docker compose"
fi

echo "== [2/6] Ollama(로컬 LLM) 설치 + 모델 pull =="
if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh
fi
sudo systemctl enable --now ollama || (nohup ollama serve >/tmp/ollama.log 2>&1 &)
sleep 3
ollama pull "$MODEL"

echo "== [3/6] AIR 클론 ($BRANCH) =="
if [ -d "$WORK/.git" ]; then
  git -C "$WORK" fetch origin "$BRANCH" && git -C "$WORK" checkout "$BRANCH" && git -C "$WORK" pull
else
  git clone --branch "$BRANCH" "$REPO_URL" "$WORK"
fi
cd "$WORK"

echo "== [4/6] llm_patcher 로컬 LLM 분기 (브랜치 소스에 포함) =="
echo "[llm] 로컬 LLM(Ollama) 분기는 feature/air-defense 소스에 이미 포함 — 패치 불필요."

echo "== [5/6] .env 생성 (강한 시크릿 자동) =="
if [ ! -f .env ]; then
  ADMIN_PW="Air-$(openssl rand -hex 6)!"
  cat > .env <<EOF
JWT_ACCESS_SECRET=$(openssl rand -hex 24)
JWT_REFRESH_SECRET=$(openssl rand -hex 24)
JWT_ACCESS_TTL_MINUTES=60
JWT_SUPER_ACCESS_TTL_HOURS=120
JWT_REFRESH_TTL_HOURS=168
ADMIN_USERNAME=admin
ADMIN_PASSWORD=$ADMIN_PW
CORS_ORIGINS=http://localhost:8081
EOF
  echo "[.env] 생성됨 — 로그인 계정: admin / $ADMIN_PW"
else
  echo "[.env] 기존 파일 유지"
fi

echo "== [6/6] 방어 lab 스택 빌드·기동 (:8081) =="
sudo docker compose -p airlab -f docker-compose.lab.yml up -d --build
echo "헬스 대기…"
for i in $(seq 1 30); do
  curl -sf http://localhost:8081/api/v1/health >/dev/null 2>&1 && { echo "[OK] AIR lab UP"; break; }
  sleep 5
  [ "$i" = 30 ] && echo "[!] 헬스 타임아웃 — 'sudo docker logs airlab-backend' 확인"
done

cat <<'NEXT'

============================================================
 준비 완료. 브라우저(호스트/게스트)에서  http://localhost:8081
 로그인: 위 [.env] 의 admin / <생성된 비번>

 ── 방어 E2E (8종 PoC → 탐지 → 로컬 LLM 자동대응 → 검증) ──
 export BASE=http://localhost:8081
 AU=admin; AP=$(grep ADMIN_PASSWORD .env | cut -d= -f2)

 # 1) 공격 PoC (예: SQLi / 음수수량 / 미지공격)
 python3 air-attack/attack.py --base $BASE --admin-user $AU --admin-pass "$AP" sqli
 python3 air-attack/attack.py --base $BASE --admin-user $AU --admin-pass "$AP" negative-qty
 python3 air-attack/attack.py --base $BASE --admin-user $AU --admin-pass "$AP" unknown

 # 2) 로컬 LLM 자동대응 (룰 생성/소스패치) — 키 없이 Ollama
 export AIR_LLM_PROVIDER=ollama          # OLLAMA_MODEL 로 모델 변경 가능
 TOKEN=$(curl -s -X POST $BASE/api/v1/auth/login -H 'Content-Type: application/json' \
   -d "{\"username\":\"$AU\",\"password\":\"$AP\"}" \
   | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['accessToken'])")
 cd air-orchestrator
 python3 responder.py --base $BASE --token "$TOKEN" --once
 #  → [✓] [LLM] 분류/패치 … (--heuristic 없이 로컬 LLM 으로 동작)

 ※ 소스패치(generate_patch)는 컴파일되는 Java 전체 파일 생성이라 7b엔 버거울 수 있음
   → 실패 시 knowledge.py 템플릿 폴백. 룰 생성(classify_and_rule)이 로컬에 더 현실적.
 ※ verify.sh 재빌드는 docker-compose.verify.yml(:8082) 사용 — 셔임으로 v2 호출됨.
============================================================
NEXT
