# Secure CI Pipeline (`feat/security-gates`)

> GitHub Actions 기반 병렬 보안 스캔 및 Security Gate 자동화.
> 본 브랜치는 vuln-lab 환경에 대해 **SAST · Dependency Scan · DAST** 를 병렬 수행하고,
> 결과를 통합 분석하여 Build/PR 단계에서 위험 기반 검증을 수행합니다.

---

## 구성 목적

* 보안 검사를 CI 단계로 이동(Shift Left)
* 병렬 스캔 기반 Pipeline 최적화
* Severity 기반 Security Gate 적용
* 취약점 결과 통합 및 Artifact 관리

---

## 기술 스택

| 영역 | 내용 |
|---|---|
| CI / 보안 파이프라인 | GitHub Actions — Semgrep(SAST) · Trivy(SCA/SBOM) · OWASP ZAP(DAST) · Security Gate · 리포트 통합/Artifact + AI 분석 |
| IR 서비스(외부) | `ir-automation/` (Python FastAPI `:8090`) — 앱 `IncidentService` → `IrForwarder` push → TTL IP차단 · Discord · reconcile |
| Backend | Java 21, Spring Boot 3.3.5, Spring Security + JJWT, MyBatis 3, SQLite |
| AIR 방어 | `com.shop.air` (DetectionFilter · DefenseRegistry · IncidentService · DynamicRuleRegistry) |
| 오케스트레이터 | `air-orchestrator/` (Python: responder.py · knowledge.py · verify.sh) — 자동 소스패치 |
| Frontend | 순수 HTML/CSS/JS SPA (+ 🛡 **AIR IR 대시보드**) |
| Infra | Docker, docker-compose(`-p airlab`), nginx `:8081` |

## 자율방어 구조 (플래그 토글)

- 취약 코드와 방어 가드가 **한 코드베이스에 공존**. `DefenseRegistry` 플래그로 전환(**기본 OFF = 취약**).
- 공격 탐지 시 AIR 가 해당 플래그를 **즉시 ON** → 같은 요청부터 차단(자율방어 폐루프).
- DB 영속 → 재기동 후에도 방어 상태 보존.

## 방어 가드

| 플래그 | 대응 취약점 |
|---|---|
| `order.qty-guard` | 음수수량 주문(잔액 증식) |
| `sql.injection-guard` | SQL Injection (`${}` 동적쿼리) |
| `xss.input-guard` | Stored XSS |
| `authz.idor-guard` | IDOR (타인 주문 열람) |
| `ddos.rate-guard` | DDoS (요청 폭주 rate-limit) |
| `ransom.massdelete-guard` | 랜섬형 대량 삭제 |
| `upload.file-guard` | 파일 업로드 (확장자 무검증·경로조작·LFI) |
| `air.detection` / `anomaly.detection` | 시그니처 탐지 / 미지공격 이상탐지(4xx·5xx 버스트) |
| `air.shield` | 이상 출처 격리(쿨다운 차단) |

## 탐지 → 대응 폐루프

1. **DetectionFilter**(인라인): SQLi(q), XSS/음수수량(본문), DDoS/랜섬(rate), 4xx/5xx 이상탐지
   + **UploadService.autoDetect**(악성 파일명/경로조작)
2. **IncidentService.report** → ① 방어 플래그 즉시 ON ② 인시던트 기록 ③ **Risk Score** 산정 ④ **Discord 경고**
3. **air-orchestrator/responder.py** → LLM/템플릿 **자동 소스패치** → `verify.sh` 재공격 검증 → 커밋

## IR 자동대응

- **Risk Score**: 유형 → severity(CRITICAL/HIGH/MEDIUM/LOW) + score(0~100). `/air/incidents` 응답에 enrich.
  (SQLi/랜섬 95, 업로드악성 90, 음수수량/경로조작 85, IDOR 80, XSS 75, DDoS 70, 이상 50~60)
- **Discord 웹훅**: 환경변수 `AIR_DISCORD_WEBHOOK`. 인시던트마다 위험도 포함 경고를 **비동기 전송**(미설정 시 no-op).
- **IR 대시보드**: `super_admin` 로그인 → 상단 **🛡 AIR** — 방어 플래그 토글 + 인시던트(위험도 뱃지/유형/IP/조치/시각) 실시간.

## AIR 제어 API (super_admin)

```
GET  /api/v1/air/defenses                 # 방어 플래그 상태
POST /api/v1/air/defenses/{key}/enable    # / disable
GET  /api/v1/air/incidents?limit=         # severity/riskScore 포함
GET  /api/v1/air/rules  · POST · DELETE /rules/{id}   # 런타임 동적 룰
```

## 빠른 시작 (vuln-lab)

```bash
# .env: JWT_ACCESS_SECRET / JWT_REFRESH_SECRET / ADMIN_PASSWORD (강하게)
#       AIR_DISCORD_WEBHOOK=<디스코드 웹훅 URL>       (선택, IR 알림)
#       AIR_TRUSTED_PROXIES=<신뢰 프록시 CIDR,...>    (선택, 기본 루프백+사설 — XFF 실IP 채택 대역)
docker-compose -p airlab -f docker-compose.lab.yml up -d --build
# 접속: http://<호스트>:8081/     로그인: super_admin 계정(.env 의 ADMIN_USERNAME / ADMIN_PASSWORD)
```
시드 데이터: 테넌트 **`demo`**(데모상점) + 상품 4 + 데모 고객 1(계정/비번은 시드 스크립트에서 설정, 잔액 50만).

## 데모 플로우

```
1) 공격      python air-attack/attack.py <시나리오> --base http://<host>:8081 \
                    --admin-user <super_admin> --admin-pass '<password>'
2) 자율방어  탐지 → 가드 자동 ON(DEFENDED) + Discord 경고 + 대시보드 인시던트
3) (선택)    air-orchestrator/responder.py 로 자동 소스패치 시연
```
시나리오: `negative-qty · sqli · xss · idor · upload · ddos · ransom · unknown` (취약=exit1 / 방어=exit0)

## 오케스트레이터 (자동 소스패치)

- `knowledge.py` : 취약 유형별 패치 템플릿/검증(음수수량·SQLi·XSS·IDOR·**업로드**)
- `responder.py` : 인시던트 폴링 → LLM/휴리스틱 패치 → `verify.sh` 재공격 검증 → 커밋
  - 무료 데모: `responder.py --heuristic` / 실제 LLM: `AIR_LLM_PROVIDER`(anthropic|gemini|groq)
- **자동패치 안전장치(#6)**: 자동 반영은 격리 브랜치(`air/auto-patch/*`)까지만 — base 직접 push/머지 없음.
  LLM 생성 패치는 검증식 + **정적 스캔**(OS실행/리플렉션/역직렬화/네트워크/난독/파괴적삭제/하드코딩키/인가무력화)을
  모두 통과해야 채택(실패 시 결정적 템플릿 폴백). LLM 패치는 **사람 리뷰 게이트**(`--allow-llm-push` 없으면 push 보류).
  `--regression` 으로 재공격 차단 확인 후 정상기능 회귀 스모크까지 수행.

## 운영 주의

- 시연 후 **`/air/rules` 전삭제**(단일 nginx IP 환경에서 IP 차단룰이 전체차단 방지). 신뢰 IP 화이트리스트는 선택.
- `.env`, `*.pem`, 웹훅 URL은 **커밋 금지**. 의도적 취약 — 격리/신뢰 IP 전용.

## 보안 특성과 한계 (데모 주의)

- **시그니처는 시연용, 실제 방어는 anomaly + guard(#7)**: `SQLI/XSS` 등 정규식 시그니처는
  인코딩·주석삽입(`/**/`)·변형 페이로드로 우회될 수 있다. 신뢰하는 방어선은 (1) 이상탐지(5xx/4xx 스캔)→
  `air.shield` 출처격리 + 동적룰, (2) 각 유형별 런타임 가드(플래그)이며, 시그니처는 데모 가독성을 위한 보조다.
- **위험도 스코어는 유형 기반 정적값(#10)**: `RiskScoring` 은 유형→점수 고정 매핑(무영속·무집계)으로,
  반복 횟수/성공 여부/노출량을 반영하지 않는다. 반복·컨텍스트 가중과 대시보드 집계는 인시던트에 severity를
  **영속(스키마 마이그레이션)** 한 뒤 확장하는 것을 향후 과제로 둔다.
- **XSS 시연의 층위(#8)**: nginx 가 `Content-Security-Policy: script-src 'self'` 를 **web·defense 양쪽
  모든 응답(`/api` 프록시 포함, server 블록 상속)** 에 적용한다(실측 확인). 따라서 same-origin 으로 저장/업로드된
  인라인 스크립트는 어느 브랜치에서도 브라우저 실행이 차단된다. `xss` 시나리오가 web 에서 VULNERABLE 로
  뜨는 것은 **앱 계층(저장/반사 시 이스케이프 누락)** 취약을 검증하기 때문이며 브라우저 alert 실행과는 별개다.
  → 정직한 시연: web 응답 JSON 에 payload 가 **미이스케이프**로 저장/반사됨을(defense 는 이스케이프됨) 보여줘
  코드계층 취약/방어를 대비. 굳이 alert 를 띄우려면 CSP 밖 컨텍스트(다운로드한 파일 `file://` 또는 CSP 완화
  데모 페이지)에서 확인하고, 이는 CSP 라는 별도 방어층 밖의 영향임을 명시한다.
- **방어기 자체 하드닝(런타임 안전성, R1~R3)**: `DetectionFilter` 는 방어기가 먼저 무너지지 않도록 —
  (1) IP별 rate/격리 카운터 맵에 **상한(기본 5만)·만료 축출**을 두어 회전 IP 공격에도 메모리
  무한증가(OOM)를 방지하고, (2) `X-Forwarded-For` 는 **신뢰 프록시(리버스프록시) 뒤에서만** 실IP로 채택하고
  그 외에는 `remoteAddr` 를 사용해 **헤더 위조를 통한 레이트리밋·격리 우회를 차단**하며(신뢰 대역은
  `AIR_TRUSTED_PROXIES`, 기본 루프백+RFC1918 사설), (3) 시그니처 정규식 스캔 입력을 **상한(64KB)으로 캡**해
  대용량 입력에 의한 CPU 소모(경미 ReDoS 표면)를 제한한다.

## 브랜치 구도

`feature/web`(취약 baseline `:80`) ↔ **`feature/air-defense`**(자율방어 `:8081`) / `feature/air-attack`(DAST) / `dev`(CI).

---

## Pipeline 구조

```text id="o3m67u"
                ┌──────────────────────────────┐
                │ Git Push / Pull Request      │
                └──────────────┬───────────────┘
                               ▼
                ┌──────────────────────────────┐
                │ GitHub Actions Workflow      │
                └──────────────┬───────────────┘
        ┌──────────────────────┼──────────────────────┐ 
        │                      │                      │
        ▼                      ▼                      ▼
┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐
│ Semgrep            │  │ Trivy              │  │ OWASP ZAP          │
│ SAST / Static      │  │ Dependency /       │  │ DAST / Runtime     │
│ Code Analysis      │  │ Image CVE          │  │ Scan               │
└────────────────────┘  └────────────────────┘  └────────────────────┘
        │                      │                      │
        └──────────────────────┼──────────────────────┘
                               ▼
                ┌──────────────────────────────┐
                │ Security Summary             │
                │ Severity & Findings Report   │
                └──────────────┬───────────────┘
                               ▼
                ┌──────────────────────────────┐
                │ Security Gate                │
                │ Build / PR Validation        │
                └──────────────┬───────────────┘
                               ▼
                ┌──────────────────────────────┐
                │ Build Validation             │
                └──────────────────────────────┘
```

---

## 병렬 보안 스캔

각 보안 도구를 독립 Job 으로 분리하여 병렬 처리 구조 구성.

| Scanner   | 역할                        |
| --------- | ------------------------- |
| Semgrep   | 정적 코드 분석                  |
| Trivy     | Dependency / Image CVE 검사 |
| OWASP ZAP | 실행 환경 대상 동적 진단            |

---

## Security Gate

Severity 기반 Build 검증 정책 적용.

| 조건               | 동작          |
| ---------------- | ----------- |
| Critical 발견      | Build Fail  |
| High 임계치 초과      | PR Block    |
| Blocking Rule 탐지 | Workflow 중단 |

---

## Summary & Artifact

각 스캐너 결과를 통합하여:

* Severity Count
* Findings Summary
* Security Status

를 자동 생성 및 Artifact 저장.

---

## 프로젝트 구조

```text id="9zvr8m"
project-root/
│
├── .github/
│   └── workflows/
│       └── security.yml
│
├── docs/
│   └── security/
│       ├── security.yml
│       ├── overview.md
│       ├── policy.md
│       ├── workflow.md
│       └── sec-summary.md
│
├── reports/
│   ├── semgrep/
│   ├── trivy/
│   ├── zap/
│   └── summary/
│
├── scripts/
│   ├── security/
│   │   ├── run-sumgrep.sh
│   │   ├── run-trivy.sh
│   │   ├── run-zap.sh
│   │   └── run-summary.sh
│   │
│   └── generate_summary.py
│
└── policy/
    ├── security_gate.py
    └── security_policy.json
```

---

## Workflow Trigger

```text id="my2ph4"
push
pull_request

branches:
- main
- dev
- feature/**
- feat/**
```

---

## 핵심 포인트

* SAST · DAST · CVE Scan 병렬 처리
* Severity 기반 Merge/Build 제어
* 통합 Security Summary 자동 생성
* Security Validation 자동화 Workflow 구성

---

## 향후 확장

* Discord / Slack Alert
* Risk Score 연계
* Runtime WAF 연동
* 실시간 Security Dashboard

---

*DevSecOps 기반 Secure CI Validation Workflow*
