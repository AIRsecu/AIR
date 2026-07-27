# AIR — DevSecOps 자율방어 통합 라인 (`dev`)

> **AIR (Automated Incident Response)** — 실시간 위협 대응 DevSecOps 자동화 팀 프로젝트(프로젝트3).
> `dev` 는 팀의 **통합 라인**으로, 취약 앱([`feature/web`](../../tree/feature/web))에
> **자율방어(`com.shop.air`)** · **IR 자동대응 서비스**(`ir-automation/`) · **자동 소스패치 오케스트레이터**(`air-orchestrator/`) 를 얹고,
> 그 위에 커밋/PR 단계의 **보안 CI/CD 파이프라인(SAST · SCA · DAST · Security Gate · 리포트 통합/AI 분석)** 을 결합한 **가장 완결된 형상**입니다.
>
> 런타임에선 공격을 스스로 **탐지 → 즉시 차단 → 인시던트 기록 → 위험도 산정 → Discord 경고 → (자동 소스패치)** 로 대응하고,
> 빌드/PR 단계에선 **자동 보안 검증(스캔 → 게이트)** 을 수행합니다.

> ⚠️ 의도적 취약점을 포함한 **vuln-lab**. 격리 스택에서 신뢰 IP 로만 구동하세요. `.env`·`*.pem`·웹훅 URL은 **커밋 금지**.

---

## dev 가 통합하는 것

| 구성 요소 | 내용 |
|---|---|
| **웹앱(테스트베드)** | 멀티테넌트 쇼핑몰 — Java 21 / Spring Boot 3.3.5 / Spring Security+JJWT / MyBatis 3 / SQLite + 순수 HTML/CSS/JS SPA(🛡 **AIR 대시보드**) |
| **자율방어** | `com.shop.air` — `DetectionFilter` · `DefenseRegistry` · `IncidentService` · `DynamicRuleRegistry`. 플래그 토글(**기본 OFF=취약**), 공격 탐지 시 **자동 ON** |
| **IR 자동대응 서비스** | `ir-automation/` (Python FastAPI `:8090`) — 앱 `IncidentService` → `IrForwarder` push → **TTL IP차단 · Discord · 주기 reconcile** |
| **오케스트레이터** | `air-orchestrator/` — `responder.py` 자동 소스패치(격리 브랜치 `air/auto-patch/*`, **사람 리뷰 게이트**) |
| **보안 CI/CD** | GitHub Actions — Semgrep(SAST) · Trivy(SCA/CVE) · OWASP ZAP(DAST) · **Security Gate** · 리포트 통합/Artifact + AI 분석 |
| **리포트 계약** | `reports/contract/` — 스캐너별 결과를 공통 Finding 계약으로 정규화 · SBOM · LLM 분석 seam |

---

## 자율방어 (런타임)

취약 코드와 방어 가드가 **한 코드베이스에 공존**한다. `DefenseRegistry` 플래그로 전환하며(**기본 OFF=취약**),
공격이 탐지되면 AIR 가 해당 플래그를 **즉시 ON** → 같은 요청부터 차단한다(자율방어 폐루프). 플래그는 DB 영속이라 재기동 후에도 보존된다.

**방어 가드**

| 플래그 | 대응 취약점 |
|---|---|
| `order.qty-guard` | 음수수량 주문(잔액 증식) |
| `sql.injection-guard` | SQL Injection (`${}` 동적쿼리) |
| `xss.input-guard` | Stored XSS |
| `authz.idor-guard` | IDOR (타인 주문 열람) |
| `ddos.rate-guard` | DDoS (요청 폭주 rate-limit) |
| `ransom.massdelete-guard` | 랜섬형 대량 삭제 |
| `upload.file-guard` | 파일 업로드(확장자 무검증·경로조작·LFI) |
| `air.detection` / `anomaly.detection` | 시그니처 탐지 / 미지공격 이상탐지(4xx·5xx 버스트) |
| `air.shield` | 이상 출처 격리(쿨다운 차단) |

**탐지 → 대응 폐루프**

1. `DetectionFilter`(인라인) + `UploadService.autoDetect` — SQLi·XSS·음수수량·DDoS·랜섬·악성업로드·4xx/5xx 이상탐지
2. `IncidentService.report` → ① 방어 플래그 즉시 ON ② 인시던트 기록 ③ **Risk Score** 산정 ④ **Discord 경고** ⑤ `IrForwarder` → IR 서비스 push
3. `air-orchestrator/responder.py` → LLM/템플릿 **자동 소스패치** → `verify.sh` 재공격 검증 → 격리 브랜치 커밋

**IR 자동대응** — 유형→severity/score(SQLi·랜섬 95 … DDoS 70, 이상 50~60), Discord 웹훅(`AIR_DISCORD_WEBHOOK`, 비동기),
IR 서비스가 공개IP를 **TTL 차단**하고 만료 시 **reconcile 자동해제**. `super_admin` 🛡 대시보드에서 방어 토글·인시던트 실시간 확인.

**AIR 제어 API (super_admin)**
```
GET  /api/v1/air/defenses                 # 방어 플래그 상태
POST /api/v1/air/defenses/{key}/enable    # / disable
GET  /api/v1/air/incidents?limit=         # severity/riskScore 포함
GET  /api/v1/air/rules  · POST · DELETE /rules/{id}   # 런타임 동적 룰
```

---

## 보안 CI/CD 파이프라인

GitHub Actions 기반 **병렬 보안 스캔 + Security Gate** 자동화. vuln-lab 에 대해 **SAST · SCA · DAST** 를 병렬 수행하고,
결과를 통합 분석하여 Build/PR 단계에서 위험 기반 검증을 수행한다(Shift Left).

```text
        Git Push / Pull Request
                  │
          GitHub Actions Workflow
     ┌────────────┼────────────┐
     ▼            ▼            ▼
  Semgrep       Trivy      OWASP ZAP
  (SAST)     (SCA/CVE)   (DAST/Runtime)
     └────────────┼────────────┘
                  ▼
        Security Summary (Severity/Findings)
                  ▼
        Security Gate (Build / PR Validation)
                  ▼
              Build Validation
```

**병렬 보안 스캔**

| Scanner | 역할 |
|---|---|
| Semgrep | 정적 코드 분석(SAST) |
| Trivy | Dependency / Image CVE 검사(SCA) |
| OWASP ZAP | 인증 세션 Spider + Active Scan(SQLi·XSS 등, DAST) |

**ZAP 인증 스캔 흐름** — ZAP Automation Framework(`scripts/security/automation.yaml`)로 인증 세션 스캔.
1. `run-zap.sh` 가 admin 로그인 → JWT 발급.
2. 스캔용 테넌트·customer 를 API로 생성 후 customer JWT 발급(CI DB 는 ephemeral, 매 실행 재생성).
3. ZAP 컨테이너에 `ZAP_CUSTOMER_TOKEN` 주입 → Replacer 규칙이 모든 요청에 `Authorization: Bearer <token>` 삽입.
4. Spider → Passive → Active Scan(SQLi·XSS 페이로드) → JSON 리포트.

**Security Gate**

| 조건 | 동작 |
|---|---|
| Critical 발견 | Build Fail |
| High 임계치 초과 | PR Block |
| Blocking Rule 탐지 | Workflow 중단 |

**Summary & Artifact** — 각 스캐너 결과를 통합해 Severity Count · Findings Summary · Security Status 를 자동 생성·Artifact 저장.
리포트 계약(`reports/contract/`)으로 정규화 후 **AI(LLM) 분석 seam** 에 전달.

---

## 프로젝트 구조

```text
project-root/
├── backend/                     # Spring Boot 앱 (com.shop.* + com.shop.air 자율방어)
│   ├── src/main/java/com/shop/air/   # DetectionFilter · DefenseRegistry · IncidentService · IrForwarder …
│   └── pom.xml
├── ir-automation/               # IR 자동대응 서비스 (Python FastAPI :8090) + tests
├── air-orchestrator/            # 자동 소스패치 (responder.py · knowledge.py · verify.sh)
├── air-attack/                  # 공격 시나리오 스크립트 (attack.py: 8종)
├── reports/                     # 스캔 결과 + contract(정규화·SBOM·LLM seam)
├── scripts/
│   ├── security/                # run-semgrep/trivy/zap.sh · automation.yaml
│   ├── generate_summary.py      # 스캐너 결과 통합 요약
│   └── ai_agent/ · llm/         # AI 분석 파이프라인
├── docs/                        # 보안 문서
├── docker-compose.lab.yml       # vuln-lab 스택 (nginx :8081 + backend + ir-automation)
└── .github/workflows/
    ├── security.yml             # 병렬 스캔 + Security Gate
    └── ir-tests.yml             # IR 서비스 단위테스트(additive)
```

---

## 빠른 시작 (vuln-lab)

```bash
# .env: JWT_ACCESS_SECRET / JWT_REFRESH_SECRET / ADMIN_USERNAME / ADMIN_PASSWORD (강하게)
#       AIR_DISCORD_WEBHOOK=<웹훅 URL>          (선택, IR 알림)
#       AIR_TRUSTED_PROXIES=<신뢰 프록시 CIDR>  (선택, 기본 루프백+사설 — XFF 실IP 채택)
docker-compose -p airlab -f docker-compose.lab.yml up -d --build
# 접속: http://<호스트>:8081/   로그인: super_admin(.env 의 ADMIN_USERNAME / ADMIN_PASSWORD)
```

**데모 플로우**
```
1) 공격      python air-attack/attack.py <시나리오> --base http://<host>:8081 \
                    --admin-user <super_admin> --admin-pass '<password>'
2) 자율방어  탐지 → 가드 자동 ON(DEFENDED) + Discord 경고 + 🛡 대시보드 인시던트 + IR TTL 차단
3) (선택)    air-orchestrator/responder.py 로 자동 소스패치 시연
```
시나리오: `negative-qty · sqli · xss · idor · upload · ddos · ransom · unknown` (취약=exit1 / 방어=exit0)

---

## 브랜치 구도

| 브랜치 | 역할 |
|---|---|
| `feature/web` | 취약 baseline (방어 없음, 공격/데모 대상) |
| `feature/air-defense` | 자율방어 적용본 (`com.shop.air` + 오케스트레이터) |
| **`dev`** | **통합 라인** — 취약앱 + 자율방어 + IR 서비스 + 보안 CI/CD 파이프라인 (본 브랜치) |
| `main` | 최종 산출물 승격 대상 |

---

## 운영 주의 / 한계

- 시연 후 **`/air/rules` 전삭제**(단일 nginx IP 환경에서 IP 차단룰이 전체차단 방지). 공격이 만든 `atk-*` 테넌트는 정리.
- **시그니처는 시연용, 실제 방어선은 이상탐지(`air.shield`)+유형별 가드** — 정규식 시그니처는 인코딩·변형으로 우회 가능.
- **Risk Score 는 유형 기반 정적값** — 반복/성공/노출량 미반영(향후 severity 영속 후 가중·집계 확장 예정).

---

*AIR — DevSecOps 실시간 위협 대응: 자율방어 런타임 + 보안 CI/CD 검증 통합.*
