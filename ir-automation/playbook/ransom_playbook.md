# Playbook: Ransom Mass-Delete (`RANSOM_MASSDELETE`)

## 개요

| 항목 | 값 |
|------|-----|
| `type` | **`RANSOM_MASSDELETE`** |
| base score | **95** |
| base severity | **CRITICAL** |
| 앱 1차 가드 | `ransom.massdelete-guard` |
| IR 자동 대응 | CRITICAL → IP 차단 · CRITICAL Discord · 긴 TTL |

> **Base score SSOT**: `RiskScoring.java` ↔ `ir/analyzer/risk.py::_SCORE` 1:1 parity

> **임계 상수** (@{{SHORT}} 기준):
> - `MASSDELETE_LIMIT = 5` (DELETE 창당 허용)
> - `WINDOW_MS = 10_000` (10초 창)
> - 위치: `backend/.../DetectionFilter.java`

> 파일명·관용상 “ransomware”와 헷갈리기 쉽지만, **암호화 랜섬웨어가 아니다.**  
> API `DELETE` 빈도 폭주(대량 파괴) 행위 탐지다. 자동 대응 대상 type은 반드시 `RANSOM_MASSDELETE`.

## Detect (앱)

| 위치 | 역할 |
|------|------|
| `DetectionFilter.java:162 (@{{SHORT}})` | API DELETE 카운트 > `MASSDELETE_LIMIT` |
| 탐지 조건 | `air.detection` ON · massdelete-guard **OFF** 일 때 report |
| 가드 ON | `429 MASS_DELETE_BLOCKED` 즉시 반환 |

`IncidentService` 가 report 시 가드를 arming → 이후 요청부터 레이트가드.

## Analyze (IR)

- base 95 / CRITICAL (SQLI와 동일 스코어 밴드)
- orchestrator `VULNS` 맵에는 **없음** — 지식 주석상 DDoS/랜섬(대량삭제)은 런타임 레이트가드가 정답, 영구 소스패치 비대상

## Contain (IR)

- CRITICAL IP 차단 + Discord CRITICAL 웹훅(설정된 경우)
- 앱 레이트가드(1차) + IR IP 격리(2차)

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

- **소스 패치 대상 아님** (`air-orchestrator/knowledge.py` 주석: 런타임 레이트가드가 정답).
- 운영 회복: 가드 유지·손상 데이터/권한 점검·필요 시 백업 복구(앱·인프라 절차; IR 코드 밖).
- `incident_store` `recover: False` 유지.

## 검증 · 롤백

### 유닛

```bash
poetry run pytest ir-automation/tests -q
# → IR suite green 확인 (작성 시점 N passed)
```

### DAST

```bash
python dast/attacks/ransom_attack.py --base http://localhost:8081
```

### 결과 확인

- 앱 DB (항상): `GET /api/v1/air/incidents`
- IR JSON (조건부): `${INCIDENT_STORAGE_PATH:-./incidents}/<id>.json`
- 필드: `type`, `risk.base_severity`, `response.action`, `playbook.recover=false`

### 롤백

- `POST /api/v1/air/defenses/ransom.massdelete-guard/disable`
- IR IP TTL / reconcile · 비상 `BLOCK_MODE=simulation`

## 관련 코드

- `DetectionFilter` mass-delete 분기
- `DefenseRegistry.RANSOM_MASSDELETE_GUARD`
- `ir/analyzer/risk.py` `RANSOM_MASSDELETE: 95`
