# Playbook: SQL Injection Attempt

## 개요

| 항목 | 값 |
|------|-----|
| `type` | `SQLI_ATTEMPT` |
| base score | **95** |
| base severity | **CRITICAL** (`score >= 90`) |
| 앱 1차 가드 | `sql.injection-guard` (`DefenseRegistry.SQL_INJECTION_GUARD`) |
| IR 자동 대응 | `should_block=True` (CRITICAL) · TTL = `CRITICAL_BLOCK_DURATION`(기본 120s) · Discord CRITICAL 웹훅 |

> **Base score SSOT**: `RiskScoring.java` ↔ `ir/analyzer/risk.py::_SCORE` 1:1 parity

## Detect (앱)

제품 검색 쿼리 `q` 에 SQLI 시그니처 매칭 시 보고.

| 위치 | 역할 |
|------|------|
| `DetectionFilter.java:178 (@{{SHORT}})` | `GET` + product search URI · `SQLI_SIGNATURE` → `report("SQLI_ATTEMPT", …)` |
| `IncidentService.java` (~43–80) | 가드 arming · DB 기록 · Discord(앱) · `IrForwarder` → IR `/ingest` |

가드 OFF일 때만 시그니처 탐지 경로가 의미 있다(탐지 ON + 가드 OFF = 취약 재현·자동 arming).

## Analyze (IR)

| 모듈 | 링크 |
|------|------|
| 정규화 | `ir/detector/normalize.py` — camelCase/snake_case → `Incident` |
| 위험도 | `ir/analyzer/risk.py` — `base_*=95/CRITICAL`; effective는 endpoint/payload/재범/야간 가중 |
| 파이프라인 | `ir/pipeline.py` `handle()` — 유형 무관 단일 경로 |

## Contain (IR)

| 모듈 | 동작 |
|------|------|
| `ir/responder/ip_blocker.py` | `base_severity` 기준 차단; allowlist·사설 IP·simulation 안전장치 적용 |
| `ir/store/incident_store.py` | `playbook.detect/analyze=True`, `contain=enforced`, **`recover=False`** |
| `ir/notifier/discord.py` | 신규 `BLOCKED` 만 사후 알림; CRITICAL URL은 **base_severity** |

앱 측 1차 차단(검색 가드 ON)과 IR 2차(지속형 IP 차단)는 역할이 다르다.

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

IR 범위 밖. `air-orchestrator` 가 소스 패치·검증·재배포를 담당한다.

- 지식 맵: `air-orchestrator/knowledge.py` `VULNS["SQLI_ATTEMPT"]`
  - 대상 파일: `ProductService.java`
  - defense_key: `sql.injection-guard`
  - scenario: `sqli`

## 검증 · 롤백

### 유닛

```bash
poetry run pytest ir-automation/tests -q
# → IR suite green 확인 (작성 시점 N passed)

poetry run pytest ir-automation/tests/test_risk.py -q  # score parity
```

### DAST 통합 (담당: gdmctb4614)

```bash
python dast/attacks/sqli_attack.py --base http://localhost:8081
```

### 결과 확인

- 앱 DB (항상): `GET /api/v1/air/incidents`
- IR JSON (조건부: `AIR_IR_INGEST_URL` + IR 기동 + `IrForwarder` 성공): `${INCIDENT_STORAGE_PATH:-./incidents}/<id>.json`
- 필드: `type`, `risk.base_severity`, `response.action`, `playbook.recover=false`

### 롤백

- 가드 disable: `POST /api/v1/air/defenses/sql.injection-guard/disable`
- 가드 목록: `GET /api/v1/air/defenses`
- IR IP: TTL 만료 or BlockStore reconcile
- 비상: `BLOCK_MODE=simulation` 강제

## 관련 코드

- 앱 SCORE: `RiskScoring.java`
- IR SCORE: `ir/analyzer/risk.py`
- 유입: `IncidentService` → `IrForwarder`
