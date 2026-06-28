# AIR — 자율 방어 PoC (음수수량 자금증식)

공격 모듈 + 인라인 탐지 + 즉시 토글 방어의 폐루프 1차 MVP.
> 흐름: **공격 → 탐지(인라인) → 즉시 방어 ON(런타임 차단) → 인시던트 기록**
> (5단계: LLM 자동 소스패치는 다음 단계에서 추가)

## 구성요소 (backend `com.shop.air`)
- `DefenseRegistry` — 방어 토글(인메모리+DB). 키: `order.qty-guard`(기본 OFF=취약), `air.detection`(기본 ON).
- `DetectionFilter` — 주문 본문의 음수/0 수량을 인라인 탐지 → `IncidentService.report`.
- `IncidentService` — 탐지 즉시 대응 방어 플래그 ON + 인시던트 기록.
- `AirController` (`/api/v1/air/**`, super_admin) — 방어 토글/조회, 인시던트 조회.
- vuln-lab: `PlaceOrderRequest`의 `@Valid` 캐스케이드 제거 + `OrderService` 가드를 `order.qty-guard`로 게이트.

## 데모 절차

준비: super_admin 토큰 얻기
```bash
BASE=http://13.125.184.233   # 또는 http://localhost (배포 호스트)
TOKEN=$(curl -s -X POST $BASE/api/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"<admin>","password":"<pw>"}' | python -c "import sys,json;print(json.load(sys.stdin)['data']['accessToken'])")
AUTH="Authorization: Bearer $TOKEN"
```

1) 현재 방어 상태 확인 (취약 상태)
```bash
curl -s $BASE/api/v1/air/defenses -H "$AUTH"
# → {"order.qty-guard": false, "air.detection": true}
```

2) **취약 시연** — 탐지를 잠시 끄고 공격 (방어/탐지 모두 OFF → 실제 익스플로잇)
```bash
curl -s -X POST $BASE/api/v1/air/defenses/air.detection/disable -H "$AUTH"
python attack.py --base $BASE --admin-user <admin> --admin-pass <pw> negative-qty
# → 🔴 VULNERABLE — 잔액 0 → 500000 (+500000)
```

3) **자율 방어 시연** — 탐지 ON + 방어 초기화 후 재공격
```bash
curl -s -X POST $BASE/api/v1/air/defenses/air.detection/enable    -H "$AUTH"
curl -s -X POST $BASE/api/v1/air/defenses/order.qty-guard/disable -H "$AUTH"   # 취약 상태로 리셋
python attack.py --base $BASE --admin-user <admin> --admin-pass <pw> negative-qty
# → 🟢 DEFENDED — 탐지 즉시 order.qty-guard 활성화 → 주문 차단
```

4) 대응 기록 확인
```bash
curl -s $BASE/api/v1/air/defenses  -H "$AUTH"   # order.qty-guard: true (자동 활성)
curl -s "$BASE/api/v1/air/incidents?limit=10" -H "$AUTH"
```

## 시나리오 2 — SQL Injection (상품 검색 필터 우회)

취약 표면: `GET /api/v1/tenants/{tid}/products/search?q=...`
- `sql.injection-guard` **OFF** → 매퍼가 `name LIKE '%${q}%'` (동적 SQL) → 인젝션 가능
- `sql.injection-guard` **ON**  → `name LIKE '%' || #{q} || '%'` (안전 바인딩) → 리터럴 처리
- 탐지: `DetectionFilter` 가 `q` 에서 SQLi 시그니처(`' OR '1'='1`, `UNION SELECT`, `--` 등) 발견 시
  `SQLI_ATTEMPT` 보고 → `IncidentService` 가 `sql.injection-guard` 즉시 ON.

```bash
# 취약 시연 (탐지 OFF → 실제 익스플로잇)
curl -s -X POST $BASE/api/v1/air/defenses/air.detection/disable      -H "$AUTH"
curl -s -X POST $BASE/api/v1/air/defenses/sql.injection-guard/disable -H "$AUTH"
python attack.py --base $BASE --admin-user <admin> --admin-pass <pw> sqli
# → 🔴 VULNERABLE — 인젝션으로 전체 상품 노출

# 자율 방어 시연 (탐지 ON + 방어 리셋 → 공격 순간 자동 차단)
curl -s -X POST $BASE/api/v1/air/defenses/air.detection/enable       -H "$AUTH"
curl -s -X POST $BASE/api/v1/air/defenses/sql.injection-guard/disable -H "$AUTH"
python attack.py --base $BASE --admin-user <admin> --admin-pass <pw> sqli
# → 🟢 DEFENDED — 탐지 즉시 sql.injection-guard 활성화 → 안전 바인딩으로 0건

curl -s $BASE/api/v1/air/defenses -H "$AUTH"             # sql.injection-guard: true
curl -s "$BASE/api/v1/air/incidents?limit=10" -H "$AUTH" # SQLI_ATTEMPT 기록
```

## 시나리오 3 — Stored XSS (상품명 스크립트 저장)

취약 표면: `POST/PATCH /api/v1/tenants/{tid}/products` 의 name·description·category
- `xss.input-guard` **OFF** → 입력 원문 저장 → 응답/렌더 시 스크립트 실행(저장형 XSS)
- `xss.input-guard` **ON**  → 위험 문자(`<`,`>`,`&`,`"`,`'`) HTML 이스케이프 → 무력화
- 탐지: `DetectionFilter` 가 본문에서 `<script`,`onerror=`,`javascript:` 등 발견 시
  `XSS_ATTEMPT` 보고 → `IncidentService` 가 `xss.input-guard` 즉시 ON.

```bash
# 취약 시연 (탐지 OFF)
curl -s -X POST $BASE/api/v1/air/defenses/air.detection/disable   -H "$AUTH"
curl -s -X POST $BASE/api/v1/air/defenses/xss.input-guard/disable -H "$AUTH"
python attack.py --base $BASE --admin-user <admin> --admin-pass <pw> xss
# → 🔴 VULNERABLE — <script> 원문 저장

# 자율 방어 시연 (탐지 ON + 방어 리셋)
curl -s -X POST $BASE/api/v1/air/defenses/air.detection/enable    -H "$AUTH"
curl -s -X POST $BASE/api/v1/air/defenses/xss.input-guard/disable -H "$AUTH"
python attack.py --base $BASE --admin-user <admin> --admin-pass <pw> xss
# → 🟢 DEFENDED — 탐지 즉시 xss.input-guard 활성화 → 이스케이프 저장
```

## 시나리오 4 — IDOR (타 고객 주문 무단 열람)

취약 표면: `GET /api/v1/tenants/{tid}/orders/{id}` (소유자/관리자만 허용해야 함)
- `authz.idor-guard` **OFF** → 소유자 검증 생략 → 다른 고객 주문 열람(IDOR)
- `authz.idor-guard` **ON**  → 소유자/관리자가 아니면 403
- 탐지: `OrderService.getByIdAuthorized` 에서 소유자/관리자가 아닌 접근 감지(서비스 계층)
  → `IDOR_ATTEMPT` 보고 → `authz.idor-guard` 즉시 ON → 같은 요청부터 차단.
  (입력 시그니처가 아니라 "행위(소유권 위반)" 기반 탐지)

```bash
# 취약 시연 (탐지 OFF)
curl -s -X POST $BASE/api/v1/air/defenses/air.detection/disable    -H "$AUTH"
curl -s -X POST $BASE/api/v1/air/defenses/authz.idor-guard/disable -H "$AUTH"
python attack.py --base $BASE --admin-user <admin> --admin-pass <pw> idor
# → 🔴 VULNERABLE — 타 고객 주문 노출

# 자율 방어 시연 (탐지 ON + 방어 리셋)
curl -s -X POST $BASE/api/v1/air/defenses/air.detection/enable     -H "$AUTH"
curl -s -X POST $BASE/api/v1/air/defenses/authz.idor-guard/disable -H "$AUTH"
python attack.py --base $BASE --admin-user <admin> --admin-pass <pw> idor
# → 🟢 DEFENDED — 소유자 검증으로 403
```

## 시나리오 5 — DDoS (요청 폭주 / rate flood)

취약 표면: 레이트리밋 부재. `DetectionFilter` 가 IP별 슬라이딩 윈도우(10초)로 카운트.
- `ddos.rate-guard` **OFF** → 무제한 허용(폭주 성공)
- `ddos.rate-guard` **ON**  → 창 내 30건 초과 시 HTTP 429
- 탐지: 창 내 30건 초과 시 `DDOS_FLOOD` 보고 → `ddos.rate-guard` 즉시 ON.
- 대상: `/api/v1/**` (제어플레인 `/api/v1/air/**` 제외). attack 은 `/api/v1/health` 폭주.

```bash
# 취약 시연 (탐지 OFF + 가드 OFF)
curl -s -X POST $BASE/api/v1/air/defenses/air.detection/disable  -H "$AUTH"
curl -s -X POST $BASE/api/v1/air/defenses/ddos.rate-guard/disable -H "$AUTH"
python attack.py --base $BASE --admin-user <admin> --admin-pass <pw> ddos
# → 🔴 VULNERABLE — 60건 전부 200

# 자율 방어 시연 (탐지 ON + 가드 리셋) — 직전 창이 비도록 ~10초 후 실행
curl -s -X POST $BASE/api/v1/air/defenses/air.detection/enable   -H "$AUTH"
curl -s -X POST $BASE/api/v1/air/defenses/ddos.rate-guard/disable -H "$AUTH"
python attack.py --base $BASE --admin-user <admin> --admin-pass <pw> ddos
# → 🟢 DEFENDED — 임계 초과분 429 차단
```
> ⚠️ `ddos.rate-guard` ON 은 모든 엔드포인트에 적용(IP당 30건/10초). 다른 시나리오
> 테스트 전엔 `ddos.rate-guard/disable` 로 꺼두는 게 안전.

## 종료코드 (검증/CI용)
`attack.py` 는 공격 성공(취약)=**1**, 방어됨=**0** 으로 종료. 5단계 자동패치 검증에서 "패치 후 0이어야 통과"로 활용.

## 배포 메모
- 새 테이블(`defense_flags`, `security_incidents`)은 `CREATE TABLE IF NOT EXISTS` + 자동 마이그레이션이라 `down -v` 불필요.
- 이 브랜치(`feature/air-defense`)는 **의도적으로 음수수량 취약점을 열어둔** vuln-lab 이다(운영 배포 금지, 테스트베드 전용).
