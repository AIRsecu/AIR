# Playbook: Malicious Upload & Path Traversal

업로드 관련 두 유형을 **한 문서**로 둔다. 앱 가드 키는 동일(`upload.file-guard`), IR 파이프라인도 동일하다.

## 개요

| `type` | base score | base severity | 탐지 초점 |
|--------|------------|---------------|-----------|
| `UPLOAD_MALICIOUS_FILE` | **90** | **CRITICAL** | 위험 확장자(웹셸/스크립트 등) · store 경로 |
| `UPLOAD_PATH_TRAVERSAL` | **85** | **HIGH** | `..` / `/` / `\` 경로조작 · **read 경로** |

| 공통 | 값 |
|------|-----|
| 앱 가드 | `upload.file-guard` |
| 보고 endpoint (고정 문자열) | `/api/v1/tenants/*/uploads` |
| IR | 유형별 base로 차단·웹훅 게이트 |

> **Base score SSOT**: `RiskScoring.java` ↔ `ir/analyzer/risk.py::_SCORE` 1:1 parity

## Detect (앱) — 호출부

| 위치 | 역할 |
|------|------|
| `UploadService.java:45 (@{{SHORT}})` `store` | `autoDetect(raw, "UPLOAD_MALICIOUS_FILE", true)` — `checkExt=true` |
| `UploadService.java:74 (@{{SHORT}})` `read` | `autoDetect(name, "UPLOAD_PATH_TRAVERSAL", false)` — `checkExt=false` |
| `UploadService.java:94 (@{{SHORT}})` `autoDetect` | `air.detection` ON · 가드 OFF일 때만 report |

> 이 경로의 `report(..., clientIp=null, …)` 이므로 IR IP 차단은 `SKIPPED_NO_IP` 일 수 있다.  
> **1차 방어는 업로드 가드 arming**이며, IR는 기록·(IP 있을 때) 2차 격리.

## Analyze (IR)

- `UPLOAD_MALICIOUS_FILE`: base 90 CRITICAL → CRITICAL TTL·CRITICAL 웹훅 후보
- `UPLOAD_PATH_TRAVERSAL`: base 85 HIGH
- 둘 다 동일 `handle()` 경로

## Contain (IR)

- `ip_blocker` / `incident_store` / `discord` 표준
- IP 없으면 네트워크 contain 없음 — `playbook.contain=false` 가능(정상)

## Notify

| 계층 | 채널 | 트리거 |
|------|------|--------|
| 앱 | Discord 탐지 웹훅 | `IncidentService.report()` (60s dedup: `type\|who`) |
| IR | Discord 대응 웹훅 | `ip_blocker` 결과 신규 `BlockAction.BLOCKED`만 |
| IR CRITICAL | `DISCORD_WEBHOOK_URL_CRITICAL` | `base_severity=CRITICAL`일 때만 |

- 안전장치: `allowed_mentions: {"parse": []}` (완화 금지)
- 역할 분리: 앱=탐지, IR=대응
- `SKIPPED_NO_IP`는 IR 사후 알림 미전송 (정상 동작) — upload에서 흔함

## Recover (orchestrator)

- `VULNS["UPLOAD_MALICIOUS_FILE"]` / `VULNS["UPLOAD_PATH_TRAVERSAL"]`
- 대상: `UploadService.java` · defense_key `upload.file-guard` · scenario `upload`
- ClamAV·FS 스냅샷 등은 **IR/본 playbook 범위 밖**

## 검증 · 롤백

### 유닛

```bash
poetry run pytest ir-automation/tests -q
# → IR suite green 확인 (작성 시점 N passed)
```

### DAST

```bash
python dast/attacks/upload_attack.py --base http://localhost:8081
```

### 결과 확인

- 앱 DB (항상): `GET /api/v1/air/incidents`
- IR JSON (조건부): `${INCIDENT_STORAGE_PATH:-./incidents}/<id>.json`
- 필드: `type`, `risk.base_severity`, `response.action`, `playbook.recover=false`

### 롤백

- `POST /api/v1/air/defenses/upload.file-guard/disable`
- IR IP TTL / reconcile · 비상 `BLOCK_MODE=simulation`

## 관련 코드

- `UploadService.java`
- `IncidentService` TYPE_TO_DEFENSE (두 type → 동일 가드)
- `ir/analyzer/risk.py` 두 키
