# Playbook: XSS Attempt

## 개요

| 항목 | 값 |
|------|-----|
| `type` | `XSS_ATTEMPT` |
| base score | **75** |
| base severity | **HIGH** (`70 ≤ score < 90`) |
| 앱 1차 가드 | `xss.input-guard` |
| IR 자동 대응 | `should_block=True` (HIGH) · TTL = `DEFAULT_BLOCK_DURATION`(기본 60s) · 기본 Discord 웹훅 |

> **Base score SSOT**: `RiskScoring.java` ↔ `ir/analyzer/risk.py::_SCORE` 1:1 parity

컨텍스트 가중으로 effective 가 CRITICAL 로 **승격될 수 있으나**, 차단·CRITICAL 웹훅·TTL 게이트는 **base_severity=HIGH** 를 유지한다 (M1).

## Detect (앱)

제품 쓰기(POST/PATCH) 본문에 XSS 시그니처 매칭 시 보고.

| 위치 | 역할 |
|------|------|
| `DetectionFilter.java:189 (@{{SHORT}})` | product write URI · `XSS_SIGNATURE` → `report("XSS_ATTEMPT", …)` |
| `IncidentService.report()` | `xss.input-guard` arming + IR forward |

## Analyze (IR)

- `normalize` → `RiskAnalyzer.assess` → `base_score=75` / `base_severity=HIGH`
- Embed divergence 시 라벨 예: `HIGH → CRITICAL (+context)` (`ir/notifier/discord.py` `_severity_label`)

## Contain (IR)

동일 파이프라인: `ip_blocker` → `incident_store` → `discord` (신규 BLOCKED만).  
LOW가 아니므로 네트워크 차단 후보(안전장치 통과 시).

## Notify

| 계층 | 채널 | 트리거 |
|------|------|--------|
| 앱 | Discord 탐지 웹훅 | `IncidentService.report()` (60s dedup: `type\|who`) |
| IR | Discord 대응 웹훅 | `ip_blocker` 결과 신규 `BlockAction.BLOCKED`만 |
| IR CRITICAL | `DISCORD_WEBHOOK_URL_CRITICAL` | `base_severity=CRITICAL`일 때만 |

- 안전장치: `allowed_mentions: {"parse": []}` (완화 금지)
- 역할 분리: 앱=탐지, IR=대응
- `SKIPPED_NO_IP`는 IR 사후 알림 미전송 (정상 동작)

## Recover (orchestrator)

- `air-orchestrator/knowledge.py` `VULNS["XSS_ATTEMPT"]`
- 대상: `ProductService.java` · defense_key `xss.input-guard` · scenario `xss`

## 검증 · 롤백

### 유닛

```bash
poetry run pytest ir-automation/tests -q
# → IR suite green 확인 (작성 시점 N passed)

poetry run pytest ir-automation/tests/test_risk.py -q
```

### DAST

```bash
python dast/attacks/xss_attack.py --base http://localhost:8081
```

### 결과 확인

- 앱 DB (항상): `GET /api/v1/air/incidents`
- IR JSON (조건부): `${INCIDENT_STORAGE_PATH:-./incidents}/<id>.json`
- 필드: `type`, `risk.base_severity`, `response.action`, `playbook.recover=false`

### 롤백

- `POST /api/v1/air/defenses/xss.input-guard/disable`
- `GET /api/v1/air/defenses`
- IR IP TTL / reconcile · 비상 `BLOCK_MODE=simulation`

## 관련 코드

- `DetectionFilter.java` XSS 분기
- `ir/analyzer/risk.py` · `ir/pipeline.py`
