# AIR 오케스트레이터 — 자동 소스패치 루프 (5단계)

별도 프로세스가 인시던트를 폴링해 **공격 → 탐지 → 즉시토글(4단계) → 자동 소스패치(5단계)** 폐루프를 완성한다.

```
/air/incidents 폴링 → 미처리(MITIGATED) → 취약위치 매핑
  → Claude API 패치 생성(claude-opus-4-8, 하이브리드; 실패 시 템플릿)
  → 격리 git 브랜치 적용
  → 검증: 런타임 가드/탐지 OFF로 공격 재현 → '소스 자체'로 차단되면 통과
  → 통과: 커밋(+선택 push), 인시던트 status=PATCHED / 실패: 롤백, status=FAILED(런타임 플래그 유지)
```

## 구성요소
- `responder.py` — 폴링·git·검증·커밋 오케스트레이션 (stdlib)
- `llm_patcher.py` — Anthropic Messages API 호출(urllib). 모델 `claude-opus-4-8`, adaptive thinking + effort high. `ANTHROPIC_API_KEY` 없으면 None → 템플릿 폴백
- `knowledge.py` — 취약점 KB(유형→파일/방어키/시나리오/템플릿/검증식)
- `verify.sh` + `../docker-compose.verify.yml` — 포트 8082 throwaway 스택으로 패치 빌드·재공격 검증
- 백엔드: `POST /api/v1/air/incidents/{id}/status` (오케스트레이터가 결과 기록)

## 사전 준비 (EC2)
패치 대상은 **git 저장소**여야 한다(브랜치/커밋). air-lab(scp본)과 별도로 클론:
```bash
git clone -b feature/air-defense https://github.com/AIRsecu/AIR.git ~/air-repo
cd ~/air-repo
# 검증 스택용 .env (lab 과 동일 형식)
cat > .env <<EOF
JWT_ACCESS_SECRET=$(openssl rand -base64 48)
JWT_REFRESH_SECRET=$(openssl rand -base64 48)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=LabAdmin!234
EOF
# (선택) LLM 사용 — 멀티 공급자(무료 옵션). 키 하나만 있으면 자동 감지.
#   무료: Gemini  → https://aistudio.google.com (Get API key, 결제 불필요)
export GEMINI_API_KEY=...                 # 선택 GEMINI_MODEL=gemini-2.0-flash
#   무료: Groq    → https://console.groq.com
# export GROQ_API_KEY=...                 # 선택 GROQ_MODEL=llama-3.3-70b-versatile
#   유료: Anthropic(크레딧 필요)
# export ANTHROPIC_API_KEY=sk-ant-...
#   공급자 강제 지정(미설정 시 키 존재로 자동 감지):
# export AIR_LLM_PROVIDER=gemini|groq|anthropic
# (선택) 자동 PR push 사용 시 git 인증 구성(토큰)
```
> 키가 하나도 없으면 LLM 호출은 None 폴백 — 소스패치는 템플릿, 이상분류는 일반 shield 유지로 안전.

## 폐루프 데모 (lab=8081 가 떠 있는 상태)
```bash
# 1) 공격 → 4단계가 탐지+즉시토글로 MITIGATED 인시던트 생성
python3 ~/air-lab/air-attack/attack.py --base http://localhost:8081 \
        --admin-user admin --admin-pass LabAdmin!234 negative-qty

# 2) 오케스트레이터가 그 인시던트를 자동 패치(검증까지)
cd ~/air-repo/air-orchestrator
python3 responder.py --base http://localhost:8081 \
        --admin-user admin --admin-pass LabAdmin!234 \
        --repo ~/air-repo --once
#  → LLM/템플릿 패치 → git 브랜치 air/auto-patch/... → verify(8082, 가드 OFF 재공격)
#  → 통과 시 커밋 + 인시던트 PATCHED
```
결과 확인:
```bash
git -C ~/air-repo log --oneline -3          # 자동 패치 커밋
git -C ~/air-repo show air/auto-patch/<id>  # 패치 내용(소스 무조건 방어)
curl -s "http://localhost:8081/api/v1/air/incidents?limit=3" -H "Authorization: Bearer $TOKEN"
```

## Stage3 — 미지(이상) 인시던트 LLM 온라인 어드바이저
시그니처가 없는 `UNKNOWN_ANOMALY` / `ANOMALY_*` 인시던트(이상탐지→일반 shield 적용된 상태)를
LLM이 분류하고 **런타임 동적 차단 룰을 자동 설치**한 뒤 광역 shield 를 완화한다(=정밀화).
```
이상탐지 → air.shield(광역, 인라인) → [orchestrator] LLM 분류(공격/유형/심각도)
  → POST /air/rules 로 정밀 룰(ip/path/query) 자동 설치 → air.shield 완화
  → incident status=PATCHED(action=LLM_RULE:<id>)   /  오탐이면 LLM_FALSE_POSITIVE + shield 해제
```
소스패치(5단계)와 달리 **git repo 불필요**(런타임 룰만 설치). 따라서 `--repo` 생략 가능.
```bash
# 0) LLM 키 1개 필요 — 무료 권장(Gemini/Groq). 없으면 분류 생략 → 일반 shield 유지
export GEMINI_API_KEY=...        # 또는 GROQ_API_KEY / ANTHROPIC_API_KEY

# 1) 미지 공격 → 이상탐지로 shield + UNKNOWN_ANOMALY 인시던트 생성
python3 ~/air-lab/air-attack/attack.py --base http://localhost:8081 \
        --admin-user qudfhr --admin-pass '3rdProject!' unknown   # 🟢 DEFENDED(shield)

# 2) 오케스트레이터가 이상 인시던트를 LLM 분류 → 동적룰 자동 설치 (repo 없이)
python3 ~/air-lab/air-orchestrator/responder.py --base http://localhost:8081 \
        --admin-user qudfhr --admin-pass '3rdProject!' --once
#  → [✓] 분류='SCAN/...' → 동적룰 설치(rid) + shield 완화
```
확인:
```bash
curl -s http://localhost:8081/api/v1/air/rules -H "$AUTH"; echo            # source=LLM 룰
curl -s "http://localhost:8081/api/v1/air/incidents?limit=3" -H "$AUTH"    # action=LLM_RULE:<id>
```
> lab 한계: 모든 트래픽이 nginx 단일 IP 로 오므로 LLM 이 IP 룰을 만들면 lab 전체에 적용될 수 있다.
> (운영의 실제 다중 클라이언트 IP 에서는 출처 정밀 차단으로 동작.) 검증 성공 기준 = 인시던트가
> 자율적으로 분류→룰 설치→PATCHED 로 전이되는 것.

## 실행 옵션
| 옵션 | 의미 |
|---|---|
| `--once` | 1회 처리 후 종료(데모). 생략 시 `--interval`(기본15s) 상시 폴링 |
| `--no-verify` | 런타임 재공격 검증 생략(빠른 데모; 빌드/차단 미확인) |
| `--push` | 검증 통과 시 `origin/air/auto-patch/...` push(원격 인증 필요) |
| `--branch-base` | 패치 분기 기준 브랜치(기본: repo 현재 브랜치) |

## 검증 의미 (핵심)
verify.sh 는 **런타임 가드(order.qty-guard)와 탐지(air.detection)를 모두 OFF**로 둔 채 공격을 재현한다.
→ 4단계의 런타임 토글 도움 없이 **패치된 소스 코드 자체**가 막아야만 통과.
미패치 상태면 같은 조건에서 공격이 성공(VULNERABLE)하므로, 통과는 곧 "소스 영구 방어 확인"이다.

## 안전장치
- 패치는 격리 브랜치 + throwaway 스택(8082, `down -v`)에서만 검증 → 운영 lab(8081) 무영향
- 검증 실패/패치 실패 시 워킹트리 롤백 + 인시던트 FAILED, **런타임 플래그는 계속 ON 유지**(4단계 방어 지속)
- vuln-lab 전용. 자동 push/재배포는 옵트인(`--push`).
