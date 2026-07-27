# Playbook: DDoS Flood (`DDOS_FLOOD`)

## 개요

| 항목 | 값 |
|------|-----|
| `type` | `DDOS_FLOOD` |
| base score | **70** |
| base severity | **HIGH** |
| 앱 1차 가드 | `ddos.rate-guard` (레이트리밋) |
| 본 문서 성격 | **운영 절차 문서** — 네트워크 계층 대응이 본령 |

> **Base score SSOT**: `RiskScoring.java` ↔ `ir/analyzer/risk.py::_SCORE` 1:1 parity

> **레이트리밋 상수** (`DetectionFilter` as-implemented):
> - `RATE_LIMIT = 30` (창당 API 요청)
> - `WINDOW_MS = 10_000` (10초 창)
> - 위치: `backend/.../DetectionFilter.java`
> - `MASSDELETE_LIMIT`은 `ransom_playbook.md` 참조 (별도 유형)

### 중요: IR IP 차단과 동일시하지 말 것

- **1차·본질적 완화**: 앱/엣지 **레이트 가드**, CDN/WAF/네트워크 ACL 등 **네트워크·트래픽 계층**.
- **IR `ip_blocker`**: 인시던트 유입 후 단일 IP TTL 격리(2차). 분산 봇넷·대역 고갈형 DDoS를 “자동 IP 차단 = DDoS 대응 완료”로 보면 안 된다.
- orchestrator도 DDoS를 영구 소스패치 대상에서 제외한다 (`knowledge.py` 주석).

IR 파이프라인은 다른 유형과 같이 HIGH면 차단 후보이나, **플레이북 의사결정은 레이트가드·인프라를 우선**한다.

## Detect (앱)

| 위치 | 역할 |
|------|------|
| `DetectionFilter#doFilterInternal` | `/api/v1/`(제어플레인 제외) API rate > `RATE_LIMIT` |
| report 조건 | detection ON · ddos rate-guard **OFF** |
| 가드 ON | `429 RATE_LIMITED` |

## Analyze (IR)

- base 70 / HIGH
- 재범·야간 가중으로 effective 승격 가능 — **차단 게이트는 여전히 base HIGH**

## Contain

| 계층 | 조치 |
|------|------|
| 앱 | `ddos.rate-guard` arming · shield/quarantine(이상탐지와 연계 가능) |
| 네트워크/엣지 | WAF rate rule, CDN, SG/NACL, upstream rate limit (팀/인프라) |
| IR | 단일 `clientIp` 차단은 **보조**. simulation 기본 · allowlist · 사설 IP 보호 유지 |

## Notify

| 계층 | 채널 | 트리거 |
|------|------|--------|
| 앱 | Discord 탐지 웹훅 | `IncidentService.report()` (60s dedup: `type\|who`) |
| IR | Discord 대응 웹훅 | `ip_blocker` 결과 신규 `BlockAction.BLOCKED`만 |
| IR CRITICAL | `DISCORD_WEBHOOK_URL_CRITICAL` | `base_severity=CRITICAL`일 때만 |

- 안전장치: `allowed_mentions: {"parse": []}` (완화 금지)
- 역할 분리: 앱=탐지, IR=대응
- `SKIPPED_NO_IP`는 IR 사후 알림 미전송 (정상 동작)
- DDoS 특이사항: 앱 60s dedup (`type|who`) + IR BLOCKED-only 로 1차 억제 있음
- 대규모 봇넷 시 알림 볼륨 재검토는 운영 백로그 (현재 상태에서는 부족 근거 없음)

## Recover (orchestrator)

- 소스 패치 비대상. 레이트가드·인프라 설정 유지/튜닝.
- `recover: False` in IR store tags.

## 검증 · 롤백

### 유닛

```bash
poetry run pytest ir-automation/tests -q
# → IR suite green 확인 (작성 시점 N passed)
```

### DAST

```bash
python dast/attacks/ddos_attack.py --base http://localhost:8081
```

### 결과 확인

- 앱 DB (항상): `GET /api/v1/air/incidents`
- IR JSON (조건부): `${INCIDENT_STORAGE_PATH:-./incidents}/<id>.json`
- 필드: `type`, `risk.base_severity`, `response.action`, `playbook.recover=false`
- IR 기록은 관측용; “차단됨 = DDoS 해소”로 해석하지 않음

### 롤백

- `POST /api/v1/air/defenses/ddos.rate-guard/disable`
- 인프라 한도 조정 · IR IP TTL / reconcile · 비상 `BLOCK_MODE=simulation`

## 관련 코드

- `DetectionFilter` DDoS 분기
- `DefenseRegistry.DDOS_RATE_GUARD`
- `ir/analyzer/risk.py` `DDOS_FLOOD: 70`
- (참고) IR `BLOCK_MODE=aws_waf|nginx` 는 **IP Set/deny** 수준 — 풀 볼륨 DDoS 전용 솔루션 아님
