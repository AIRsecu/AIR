# Playbook: Order Negative Quantity

## 개요

| 항목 | 값 |
|------|-----|
| `type` | `ORDER_NEGATIVE_QTY` |
| base score | **85** |
| base severity | **HIGH** |
| 앱 1차 가드 | `order.qty-guard` |
| IR 자동 대응 | HIGH → IP 차단 후보 · 기본 Discord |

> **Base score SSOT**: `RiskScoring.java` ↔ `ir/analyzer/risk.py::_SCORE` 1:1 parity

음수/0 수량으로 주문 total 조작을 노리는 비즈니스 로직 공격.

## Detect (앱)

| 위치 | 역할 |
|------|------|
| `DetectionFilter.java:216 (@a94a8dd)` `detectNegativeQty` | 주문 생성 POST 본문 `items[].quantity <= 0` → `report("ORDER_NEGATIVE_QTY", …)` |
| `OrderService` 생성 경로 | `order.qty-guard` ON 시 라인 수량 거부; OFF 시 취약(음수 total) |

탐지(필터)와 가드(서비스)가 분리되어 있다. 보고 시 `IncidentService` 가 가드를 즉시 ON.

## 공격 변종 (DTO=`Integer quantity`, as-implemented)

- `quantity: -1` (기본 음수)
- `quantity: 0` (총액 0원 우회 시도)
- `quantity: -2147483648` (Integer.MIN_VALUE 언더플로우)

(`1e-10` 등 float 우회는 DTO 바인딩 400 예상 — 이 코드베이스에서 미검증)

→ **본질 방어**: 서비스 레이어 strict positive integer 검증 (`order.qty-guard`)

## Analyze (IR)

- base 85 / HIGH
- payload에 주문 body 일부가 실릴 수 있음 → 컨텍스트 payload 가중 가능

## Contain (IR)

표준 파이프라인. CRITICAL이 아니므로 CRITICAL 전용 웹훅 미사용(기본 URL).

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

- `VULNS["ORDER_NEGATIVE_QTY"]` → `OrderService.java` · `order.qty-guard` · scenario `negative-qty`
- 영구 패치는 서비스 레이어 검증 고정이 목표; IR는 IP 격리만

## 검증 · 롤백

### 유닛

```bash
poetry run pytest ir-automation/tests -q
# → IR suite green 확인 (작성 시점 N passed)

poetry run pytest ir-automation/tests/test_risk.py -q
```

### DAST

```bash
python dast/attacks/neg_qty_attack.py --base http://localhost:8081
```

### 시나리오 A: 탐지 ON (프로덕션 기본)

필터가 `report` → `IncidentService.report()`가 동기 arming → **같은 요청부터 400**.

```bash
curl -X POST http://localhost:8081/api/v1/tenants/{tid}/orders \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"items":[{"productId":"<pid>","quantity":-1}]}'
```

- 응답: **400** `AppException.badRequest`
- 가드 상태: `order.qty-guard = ON` (자동 arming)
- 인시던트 확인 (2계층):
  1. **앱 DB (항상 생성 — SSOT):** `GET /api/v1/air/incidents`
  2. **IR JSON (조건부):** `AIR_IR_INGEST_URL` 설정 + IR 기동 + `IrForwarder` 성공일 때만  
     `${INCIDENT_STORAGE_PATH:-./incidents}/<id>.json`  
     → 파일 없음 ≠ 인시던트 없음 (앱 DB 확인 우선)

### 시나리오 B: 탐지 OFF + 가드 OFF (vuln-lab 재현)

의도적 취약 재현 모드. 사전: `air.detection` OFF, `order.qty-guard` OFF.

```bash
curl -X POST http://localhost:8081/api/v1/tenants/{tid}/orders \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"items":[{"productId":"<pid>","quantity":-1}]}'
```

- 응답: **200** + total 음수 계산 (취약)
- 인시던트: 미생성 (탐지 OFF)

### 결과 확인

- 필드: `type`, `risk.base_severity`, `response.action`, `playbook.recover=false`

### 롤백

- `POST /api/v1/air/defenses/order.qty-guard/disable`
- `GET /api/v1/air/defenses`
- IR IP TTL / reconcile · 비상 `BLOCK_MODE=simulation`

## 관련 코드

- `DetectionFilter.detectNegativeQty`
- `OrderService` qty-guard 분기
- `ir/pipeline.py`
