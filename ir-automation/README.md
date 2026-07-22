# IR Automation

실시간 DevSecOps 보안 운영 자동화의 **IR(Incident Response) 사후 대응** 모듈.

앱(Java `com.shop.air`)이 공격을 탐지하고 즉시 1차 차단(가드 arming)을 하면,
이 모듈은 그 인시던트를 받아 **지속형 IP 차단·기록·사후 알림**(2차 대응)을 담당한다.

## 파이프라인

```
수신 이벤트(앱 POST /ingest)
  → detector.normalize   원시 dict → Incident(공용 계약, 앱과 1:1)
  → analyzer.risk        RiskScore/Severity 산정(앱 RiskScoring 과 동일 값)
  → responder.ip_blocker IP 차단(mode 분기) + TTL + 멱등 + allowlist
  → store.incident_store incidents/<id>.json 저장(NIST IR 단계 태깅)
  → notifier.discord     '사후 대응 완료' 알림(앱 1차 탐지 알림과 역할 분리)
```

모든 모듈은 `ir/models/incident.py` 의 **Incident** 를 공용 계약으로 사용한다.
필드는 앱 `SecurityIncident` 와 동일: `id/type/endpoint/clientIp/actor/payload/actionTaken/status/createdAt`.

## 차단 모드 (responder)

`.env` 의 `BLOCK_MODE` 로 분기. **기본값 `simulation`** — 실 IP 를 건드리지 않는다.

| 모드 | 동작 | 필요 |
|------|------|------|
| `simulation` | 로그만(데모/로컬/CI). BlockStore 에는 기록됨 | 없음 |
| `nginx` | `deny.conf` 를 활성목록으로 재생성 + reload | nginx include 설정 |
| `aws_waf` | WAFv2 IP Set 을 활성목록으로 교체 | `pip install '.[waf]'`, IAM |

### 안전장치 (오차단 방지)
- **allowlist**: `ALLOWLIST_IPS` (정확 IP 또는 CIDR) 는 차단 제외
- **사설/루프백 보호**: `BLOCK_PRIVATE_IPS=false`(기본) 면 RFC1918·loopback 은 절대 차단 안 함
- **저위험 skip**: LOW 등급은 기록/알림만, 네트워크 차단 안 함
- **TTL 자동 해제**: 만료 IP 는 reconcile 시 활성목록에서 빠져 자동 해제(룰 무한누적 방지).
  이벤트 수신 시 + `RECONCILE_INTERVAL_SECONDS` 마다 주기적으로도 실행 → 트래픽이 끊겨도 제때 풀림.
- **멱등성**: 이미 차단 중인 IP 는 재집행·재알림 없이 TTL 만 재무장(rearm)
- **인덱스는 IP/type 당 최근 1000건 유지** (`incident_meta/`). 더 오래된 건
  `incidents/<id>.json` 개별 조회는 가능하지만 `find()` 결과에는 안 나옴.
  통계 `top_ips` 는 trim 과 무관한 `_ip_counts` 누적 카운터 기준(상위 20).

### 인덱스 락 타임아웃 복구 (수동)

`incident_meta/.lock` 획득이 2초 내 실패하면 해당 이벤트의 stats/index 갱신은 **skip** 됩니다.
원본 `incidents/<id>.json` 은 이미 저장된 상태라 손실 없습니다.

- `StatsIndex.__init__` 은 **경로만 설정**하며 `incidents/*.json` 을 재스캔하지 **않습니다**.
- `incident_meta/` 를 지우고 재기동하면 **빈 인덱스**로 시작하며, 이후 `record()` 된 건만 반영됩니다.
- 기존 json 자동 재인덱싱 / `rebuild` API 는 **없음** (후속 티켓).

수동 절차: IR 정지 → `incident_meta/` 삭제 → 재기동 → (필요 시) 신규 이벤트로 인덱스 재적재.

> nginx 모드 주의: `deny` 는 access 단계에서 평가되므로 `return`/정적 응답으로 조기 종료되는
> 경로에는 적용되지 않는다. 실제 보호 대상인 `/api/` 프록시 트래픽에는 정상 적용됨. 또한 엣지
> nginx 가 `realip`(set_real_ip_from + real_ip_header X-Forwarded-For)로 실 클라이언트 IP 를
> `$remote_addr` 로 잡아야 앱 clientIp 와 deny 대상이 일치한다.

## 실행

```bash
# 팀 레포 루트에서 (poetry)
poetry install
cp ir-automation/.env.example ir-automation/.env   # .env 에 Discord/모드 설정

# ir-automation/ 에서 API 기동
uvicorn ir.app:app --host 0.0.0.0 --port 8090
```

### 앱 연동 (유입) — 앱 push 방식 확정
앱 `IncidentService.report()` 가 인시던트를 만든 뒤 `IrForwarder`(com.shop.air)가
`POST /ingest` 로 그 JSON(camelCase 계약)을 비동기 전달한다. dedup 통과분만 보내
IR 쪽 플러딩도 억제된다. 앱이 죽어도 IR, IR 이 죽어도 앱 요청은 영향 없음(best-effort).

앱 컨테이너 env 로 대상 주소 주입(미설정 시 no-op):
```
AIR_IR_INGEST_URL=http://<ir-host>:8090/ingest
# 같은 EC2 에서 uvicorn 을 호스트에 띄우면: http://host.docker.internal:8090/ingest
```

### 배포 검증 절차 (EC2)
1. IR 기동:  `uvicorn ir.app:app --host 0.0.0.0 --port 8090`  (BLOCK_MODE=simulation)
2. 앱 재배포: `docker-compose -f docker-compose.lab.yml up -d --build`  (AIR_IR_INGEST_URL 설정)
3. 공격 1발: air-attack sqli → 앱 로그 `[AIR->IR] ingest 전달` 확인
4. IR 확인:  `curl http://localhost:8090/blocklist`  에 공격 IP 가 잡히는지
5. 데모 후:  simulation 이라 실차단 없음. nginx 실모드 전환 시 `/air/rules` 및 deny.conf 정리

로그 tail 은 폴백 경로(앱 push 불가 환경용).

### 엔드포인트
- `POST /ingest` — 인시던트 수신 → 대응 실행
- `GET /healthz` — 상태(mode, discord 활성 여부)
- `GET /blocklist` — 현재 활성 차단(TTL 남은 것)
- `GET /incidents/{id}` — 저장된 인시던트 레코드

## 테스트

```bash
# ir-automation/ 에서
pytest -q
```
`tests/` : 모델 계약 / RiskScore 일치 / 차단 TTL·멱등·allowlist / 파이프라인·API.

## 폴더 구조
- `config/`         : 설정(`.env` 로더)
- `ir/detector/`    : 이벤트 정규화
- `ir/analyzer/`    : 위험도 분석
- `ir/responder/`   : IP 차단(핸들러: simulation/nginx/aws_waf) + TTL 블록리스트
- `ir/notifier/`    : Discord 사후 대응 알림
- `ir/store/`       : 인시던트 영속(JSON)
- `ir/models/`      : 공용 계약(Incident)
- `ir/pipeline.py`  : 전체 흐름 조립
- `ir/app.py`       : FastAPI 진입점
