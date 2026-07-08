# DAST 공격 스크립트

AIR vuln-lab(`feature/air-defense`, `:8081`) 대상 취약점 유형별 공격 시나리오 자동화 스크립트.  
방어 가드 활성 여부에 따라 **DEFENDED**(종료코드 `0`) 또는 **VULNERABLE**(종료코드 `1`)을 판정한다.

## 공통

- 실행: `poetry run python <스크립트> --base <URL> [--admin-user <u> --admin-pass <pw>]`
- 패턴: 로그인 → 테넌트/데이터 준비 → 공격 요청 → 판정
- `ddos_attack.py`, `anomaly_attack.py`는 인증 불필요

## 스크립트

| 파일 | 공격 유형 | 대상 엔드포인트 | 방어 가드 |
|---|---|---|---|
| `sqli_attack.py` | SQL Injection | `GET /products/search?q=` | `sql.injection-guard` |
| `xss_attack.py` | Stored XSS | `POST /products` (name 필드) | `xss.input-guard` |
| `neg_qty_attack.py` | 음수 수량 주문 | `POST /orders` | `order.qty-guard` |
| `idor_attack.py` | IDOR | `GET /orders/{oid}` | `authz.idor-guard` |
| `ddos_attack.py` | DDoS Rate Flood | `GET /health` | `ddos.rate-guard` |
| `ransom_attack.py` | 대량 삭제 | `DELETE /products/{pid}` | `ransom.massdelete-guard` |
| `upload_attack.py` | 파일 업로드 (위험 확장자·경로조작·LFI) | `POST /uploads`, `GET /uploads/download` | `upload.file-guard` |
| `anomaly_attack.py` | 이상탐지 (4xx Scan) | `GET /no-such-endpoint` | `anomaly.detection` + `air.shield` |
| `rowcap_attack.py` | 대량 데이터 수집 | `GET /products` | `invariant.row-cap` |

엔드포인트 공통 prefix: `/api/v1/tenants/{tenantId}/...`

## 실행 예시

```powershell
# DEFENDED (기본값 — air.detection=ON 상태에서 자율방어 폐루프 시연)
poetry run python sqli_attack.py --base http://localhost:8081 --admin-user admin --admin-pass <pw>

# VULNERABLE — 해당 가드를 비활성화한 뒤 실행
# POST /api/v1/air/defenses/sql.injection-guard/disable  (super_admin)
poetry run python sqli_attack.py --base http://localhost:8081 --admin-user admin --admin-pass <pw>
```

## 자동화 실행 (`run_all.py`)

공격 스크립트 전체를 순차 실행하고 결과를 통일 포맷 JSON으로 저장한다.

```powershell
poetry run python dast/run_all.py --base http://localhost:8081 --admin-user admin --admin-pass <pw>
```

- 출력: `reports/dast/dast-results.json` (gitignore 대상 — 로컬 생성 파일)
- `findings` 배열에는 **VULNERABLE 판정만** 포함된다. DEFENDED는 콘솔 출력으로만 표시된다.
- 새 스크립트 추가 시 `run_all.py`의 `SCRIPTS` 리스트에 항목 1개를 추가한다.

## 주의사항

- **`upload_attack.py` VULNERABLE 시연** — `air.detection` 외에 `upload.file-guard`도 비활성화해야 한다. 방어 시연 중 autoDetect가 `upload.file-guard`를 자동으로 ON하기 때문이다.
- **`anomaly_attack.py` DEFENDED 시연 후** — `air.shield`가 자동 활성화되므로 복원 시 비활성화한다.
- **`rowcap_attack.py`** — 로컬 vuln-lab 전용. 실행 후 상품 250개가 DB에 잔류하며, API 삭제는 `ransom.massdelete-guard`를 트리거하므로 Docker 재시작으로 초기화한다.
  ```powershell
  docker compose -p airlab -f docker-compose.lab.yml restart
  ```
- **가드 복원** — 테스트 후 `air.detection=ON`, 각 가드=`OFF` 기본값으로 복원한다.
