# IR Playbook (문서)

운영자가 유형별로 **탐지 → 분석 → 격리 → 회복**을 따라가기 위한 Markdown 플레이북이다.

> **Playbook ≠ Python 엔진.** 유형별 `BasePlaybook` / `sqli.py` 같은 코드 경로는 없다.  
> 런타임 자동 대응은 `ir/pipeline.py` 단일 경로(`normalize → assess → block → save → notify`)이며,  
> `incident_store` 의 `playbook: {detect, analyze, contain, recover}` 는 **JSON 태그**일 뿐이다 (`recover: False` = orchestrator 담당).

## 인덱스

| 문서 | `type` | base score | base severity | 자동 대응(IR) |
|------|--------|------------|---------------|---------------|
| [sqli_playbook.md](./sqli_playbook.md) | `SQLI_ATTEMPT` | 95 | CRITICAL | IP 차단 + Discord |
| [xss_playbook.md](./xss_playbook.md) | `XSS_ATTEMPT` | 75 | HIGH | IP 차단 + Discord |
| [idor_playbook.md](./idor_playbook.md) | `IDOR_ATTEMPT` | 80 | HIGH | IP 차단 + Discord |
| [order_negqty_playbook.md](./order_negqty_playbook.md) | `ORDER_NEGATIVE_QTY` | 85 | HIGH | IP 차단 + Discord |
| [upload_playbook.md](./upload_playbook.md) | `UPLOAD_MALICIOUS_FILE` / `UPLOAD_PATH_TRAVERSAL` | 90 / 85 | CRITICAL / HIGH | IP 차단 + Discord |
| [ransom_playbook.md](./ransom_playbook.md) | `RANSOM_MASSDELETE` | 95 | CRITICAL | IP 차단 + Discord |
| [ddos_playbook.md](./ddos_playbook.md) | `DDOS_FLOOD` | 70 | HIGH | **문서 중심** — 네트워크/레이트가드 우선; IR IP 차단과 동일시하지 않음 |

점수·등급 SSOT: 앱 `RiskScoring.java` ↔ IR `ir/analyzer/risk.py` `_SCORE` (1:1).

## Playbook 미작성 (런타임 동작은 있음)

- `ANOMALY_5XX_BURST`, `ANOMALY_SCAN`
- 런타임 대응 (실측): `raiseAnomaly` → `quarantine` + `air.shield` 폴백 arming + IR forward
- 유형별 playbook 문서는 미작성 (일반 anomaly 대응은 shield 가드로 통일)
- **"관측만" 아님** — 격리·가드 폴백 동작 중

## 보류

- **`BRUTEFORCE`** — DAST 시나리오 있으나 앱 `report("BRUTEFORCE_ATTEMPT")` 배선 없음 → 팀 협의 후 문서화
- **`Rowcap`** — 가드(`invariant.row-cap`)는 존재하나 `attack_type=None` (인시던트 경로 없음)

## 인시던트 저장 구조

- **앱 DB 인시던트** (항상 생성 — SSOT):
  - `GET /api/v1/air/incidents`
  - `incidentMapper.insert`로 매 report 시 기록
- **IR JSON 파일** (조건부):
  - 경로: `${INCIDENT_STORAGE_PATH:-./incidents}/<id>.json`
  - 필요 조건: `AIR_IR_INGEST_URL` 설정 + IR 기동 + `IrForwarder` 성공
  - 파일 없음 ≠ 인시던트 없음 (앱 DB 확인 우선)

> 로컬/vuln-lab에서 IR 미기동 시 IR JSON 없음이 정상.  
> 온콜은 **앱 DB API를 SSOT로**, IR JSON은 보조 조회.

## 공통 파이프라인 (모든 유형)

```
앱 IncidentService.report() → IrForwarder → POST /ingest
  → ir/detector/normalize.py
  → ir/analyzer/risk.py        (base_* = 앱 parity; score/severity = effective)
  → ir/responder/ip_blocker.py (차단 게이트 = base_severity; LOW 비차단)
  → ir/store/incident_store.py (NIST 태그; recover=False)
  → ir/notifier/discord.py     (CRITICAL 전용 웹훅 = base_severity)
```

### M1 정책 (유지)

- `base_score` / `base_severity` = 유형 기준 (앱 parity)
- `score` / `severity` = 컨텍스트 가중 effective (기록·Embed)
- Discord CRITICAL 웹훅 · `should_block` · TTL = **base_severity**
- Embed divergence 시: `HIGH → CRITICAL (+context)` 형태 표기

### 안전장치 (완화 금지)

- `BLOCK_MODE` 기본 `simulation`
- 사설/루프백 보호 (`BLOCK_PRIVATE_IPS=false` 기본)
- LOW 비차단 · allowlist · Discord `allowed_mentions: {"parse": []}`

## 역할 경계

| 단계 | 담당 |
|------|------|
| Detect (시그니처·가드 arming) | 앱 `com.shop.air` |
| Analyze / Contain (IP 차단·기록·사후 알림) | `ir-automation` |
| Recover (소스 패치·재배포) | **air-orchestrator** — IR에 가져오지 않음 |

## 문서 갱신 규칙

신규 `type` 추가 시:

1. `RiskScoring.java` + `ir/analyzer/risk.py::_SCORE` 동시 갱신 (parity 필수)
2. 본 README 인덱스 표 갱신
3. 유형별 playbook 문서 신설 (기존 8종 구조 준수)
4. 파일:라인 인용부는 작성 시점 커밋 앵커 명시

## 커밋 앵커 정책

각 문서의 `@<short-sha>`는 **문서 작성 시점 검증 기준**입니다.  
리팩터로 라인 밀림 시 하단 `rg` 명령으로 재확인 후 patch-set 갱신.

작성 중 placeholder: `@{{SHORT}}` — PR push 직전(또는 로컬 pin 커밋)에 short SHA로 치환.

## 파일:라인 인용 정책

- 각 문서의 백엔드 인용은 **작성 시점 커밋 앵커** 명시
- 리팩터로 라인 밀림 → 본 README 하단 `rg` 명령으로 재확인
- 대량 밀림 시 patch-set으로 일괄 갱신

## 트리거 라인 주의

백엔드 `file:line` 은 작성 시점 grep 기준이다. 리팩터 후 어긋날 수 있으니 재확인:

```bash
rg -n 'report\("(SQLI_ATTEMPT|XSS_ATTEMPT|IDOR_ATTEMPT|ORDER_NEGATIVE_QTY|UPLOAD_|RANSOM_MASSDELETE|DDOS_FLOOD)' backend --type java
```
