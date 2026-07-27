# Playbook: IDOR Attempt

## 개요

| 항목 | 값 |
|------|-----|
| `type` | `IDOR_ATTEMPT` |
| base score | **80** |
| base severity | **HIGH** |
| 앱 1차 가드 | `authz.idor-guard` |
| IR 자동 대응 | HIGH → IP 차단 후보 · 기본 Discord |

> **Base score SSOT**: `RiskScoring.java` ↔ `ir/analyzer/risk.py::_SCORE` 1:1 parity

## Detect (앱)

주문 단건 조회 시 소유자/테넌트 관리자가 아닌 접근.

| 위치 | 역할 |
|------|------|
| `OrderService#getByIdAuthorized` | 비소유 접근 + `air.detection` ON → `report("IDOR_ATTEMPT", …)` |
| 가드 ON | `AppException.forbidden` 로 같은 요청부터 차단 |
| 가드 OFF | 취약: 타인 주문 반환 (데모용) |

`clientIp` 는 이 경로에서 `null` 로 보고될 수 있다(`actor`=username). IR는 IP 없으면 `SKIPPED_NO_IP` — **기록·앱 가드는 동작**, 네트워크 차단은 스킵.

## Analyze (IR)

- `normalize` / `risk`: base 80 / HIGH
- IP 부재 시 contain 태그 `enforced=false` 가능 — 정상

## Contain (IR)

- IP 있으면 `ip_blocker` 일반 경로
- IP 없으면 차단 스킵 + Discord도 신규 BLOCKED가 아니므로 사후 웹훅 미전송 가능  
  → 앱 Discord(탐지 알림)와 IR Discord(사후 대응) 역할 분리 유지

## 알려진 한계

- IR IP 차단은 **인증 세션 공격**(IDOR)에 부적합
- user-level 차단·세션 무효화는 앱 레이어 (`authz.idor-guard`) 담당
- `report()` 호출부에서 `clientIp=null, actor=username`로 전달됨 (`OrderService` 실측)
- IR는 IP 있을 때만 2차 격리 (`SKIPPED_NO_IP` 정상)
- `actor=username`은 기록되지만 IR가 user 차단 액션 없음 (설계상)

## Notify

| 계층 | 채널 | 트리거 |
|------|------|--------|
| 앱 | Discord 탐지 웹훅 | `IncidentService.report()` (60s dedup: `type\|who`) |
| IR | Discord 대응 웹훅 | `ip_blocker` 결과 신규 `BlockAction.BLOCKED`만 |
| IR CRITICAL | `DISCORD_WEBHOOK_URL_CRITICAL` | `base_severity=CRITICAL`일 때만 |

- 안전장치: `allowed_mentions: {"parse": []}` (완화 금지)
- 역할 분리: 앱=탐지, IR=대응
- `SKIPPED_NO_IP`는 IR 사후 알림 미전송 (정상 동작) — IDOR에서 흔함

## Recover (orchestrator)

- `VULNS["IDOR_ATTEMPT"]` → `OrderService.java` · `authz.idor-guard` · scenario `idor`

## 검증 · 롤백

### 유닛

```bash
poetry run pytest ir-automation/tests -q
# → IR suite green 확인 (작성 시점 N passed)
```

### DAST

```bash
python dast/attacks/idor_attack.py --base http://localhost:8081
```

### 결과 확인

- 앱 DB (항상): `GET /api/v1/air/incidents`
- IR JSON (조건부): `${INCIDENT_STORAGE_PATH:-./incidents}/<id>.json`
- 필드: `type`, `risk.base_severity`, `response.action`, `playbook.recover=false`

### 롤백

- `POST /api/v1/air/defenses/authz.idor-guard/disable`
- IR IP TTL / reconcile · 비상 `BLOCK_MODE=simulation`

## 관련 코드

- `OrderService.getByIdAuthorized`
- `IncidentService` TYPE_TO_DEFENSE `IDOR_ATTEMPT`
- `ir/responder/ip_blocker.py` `SKIPPED_NO_IP`
