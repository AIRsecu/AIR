# Secure CI & AI DevSecOps Pipeline

> GitHub Actions 기반 병렬 보안 스캔, AI 자율 검증 및 Security Gate 자동화.
> vuln-lab 환경에 대해 **SAST · AST-based SAST · Dependency Scan · DAST · API Fuzzing** 을 병렬 수행하고,
> LangGraph 기반 AI 에이전트가 오탐(False Positive)을 자율적으로 분석·검증하여 Build/PR 단계에서 위험 기반 검증을 수행합니다.

---

## 구성 목적

* 보안 검사를 CI 단계로 이동(Shift Left)
* 병렬 스캔 기반 Pipeline 최적화
* AI 에이전트를 활용한 오탐 판별 및 경고 피로도 최소화
* Severity 기반 Security Gate 적용
* 취약점 결과 통합 및 Artifact 관리

---

## 기술 스택

| 영역 | 내용 |
| --- | --- |
| CI | GitHub Actions |
| SAST | Semgrep (정적 코드 분석) |
| Advanced SAST | CodeQL (Data Flow 기반 심층 추적) |
| Dependency Scan | Trivy |
| DAST | OWASP ZAP (인증 + Active Scan) |
| API Fuzzing | Schemathesis (Swagger 자동 생성 연동) |
| **AI Agent** | **LangGraph (7-Phase Architecture), LLMs** |
| Reporting | GitHub Artifact / Summary / AI Markdown |

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
  ┌───────────────┬────────────┼────────────┬───────────────┐ 
  ▼               ▼            ▼            ▼               ▼
┌─────────┐ ┌─────────┐ ┌────────────┐ ┌─────────┐ ┌──────────────┐
│ Semgrep │ │ CodeQL  │ │ Trivy      │ │ ZAP     │ │ Schemathesis │
│ SAST    │ │ Adv.SAST│ │ Dependency │ │ DAST    │ │ API Fuzzing  │
└─────────┘ └─────────┘ └────────────┘ └─────────┘ └──────────────┘
  │               │            │            │               │
  └───────────────┴────────────┼────────────┴───────────────┘
                               ▼
                ┌──────────────────────────────┐
                │ Data Extraction (Lightweight)│
                └──────────────┬───────────────┘
                               ▼
                ┌──────────────────────────────┐
                │    AI Agentic Validation     │
                │ (LangGraph 7-Phase Pipeline) │
                └──────────────┬───────────────┘
                               ▼
                ┌──────────────────────────────┐
                │ Integrated Security Summary  │
                │ AI Final Report & Findings   │
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

| Scanner | 역할 |
| --- | --- |
| Semgrep | 빠르고 넓은 범위의 정적 코드 분석 |
| CodeQL | 소스 코드부터 취약점 발생 지점까지의 Data Flow 심층 추적 |
| Trivy | Dependency / Image CVE 검사 |
| OWASP ZAP | 인증된 세션으로 Spider + Active Scan (SQLi·XSS 등) |
| Schemathesis | OpenAPI(Swagger) 스펙 기반 API Fuzzing 테스트 |

---

## ZAP 인증 스캔 흐름

ZAP은 Automation Framework(`scripts/security/automation.yaml`)를 통해 인증된 세션으로 스캔한다.

1. `run-zap.sh`가 admin 계정으로 로그인해 JWT를 발급받는다.
2. 스캔용 테넌트·customer 계정을 API로 생성하고 customer JWT를 발급한다.
   (CI DB는 ephemeral이므로 매 실행 시 재생성. BootstrapRunner는 admin만 생성하므로 직접 생성 필요.)
3. ZAP 컨테이너에 `ZAP_CUSTOMER_TOKEN` 환경변수로 JWT를 전달한다.
4. `automation.yaml`의 Replacer 규칙이 모든 요청에 `Authorization: Bearer <token>` 헤더를 주입한다.
5. Standard Spider → Passive Scan → Active Scan (SQLi·XSS 페이로드 주입) → JSON 리포트 순으로 실행된다.

## AI 자율 검증 파이프라인 (LangGraph)

스캐너의 맹목적인 경고를 불신(Zero-Trust)하며, 단일 책임 원칙(SRP)에 따라 7개의 독립된 노드가 오탐을 판별하고 해결책을 제시.

1. **[Phase 1] 탐색가 (Explorer):** 스캐너 종류에 맞춰 도구(`search_files`, `read_file_range`)를 자율 사용하여 팩트(코드 요약, 감사 추적 로그) 수집
2. **[Phase 2] 오탐 판별기 (Triage):** 수집된 증거를 바탕으로 프레임워크 방어 로직 등을 고려하여 오탐(FP) / 정탐(TP) 여부 판결
3. **[Phase 3] 1차 검증기 (Logic Validator):** 탐색 도구 사용의 적절성과 판별 논리 교차 검증 (실패 시 타겟을 지정하여 원인 노드로 회귀)
4. **[Phase 4] 근본 원인 분석기 (Root Cause):** 1차 검증을 통과한 정탐(TP)에 한해 근본 원인 도출 및 패치 코드 작성
5. **[Phase 5] 2차 검증기 (Code Validator):** 수정 코드의 문법적 안전성 및 환각(Hallucination) 여부 검증
6. **[Phase 6] 위험도 재평가 (Risk Assessor):** 인프라 및 비즈니스 임팩트를 고려하여 최종 위험도 산정
7. **[Phase 7] 리포터 (Reporter):** 마크다운 형태의 통합 보고서 렌더링. 최대 재시도(Loop-back) 초과 시 서킷 브레이커(Circuit Breaker)가 발동하여 경고 배너 삽입

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
* Scanner Raw & Extracted JSON
* AI Final Markdown Report (오탐 여부, 원인 분석, 권장 패치 코드 포함)

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
│   ├── codeql/
│   ├── trivy/
│   ├── zap/
│   ├── openapi/
│   └── summary/
│       └── ai_final_report.md
│
├── scripts/
│   ├── security/
│   │   ├── run-semgrep.sh
│   │   ├── run-trivy.sh
│   │   ├── run-zap.sh
│   │   ├── automation.yaml    # ZAP Automation Framework 설정
│   │   └── run-summary.sh
│   │   └── run-schemathesis.sh
│   │
│   ├── ai_agent/
│   │   └── requirements.txt
│   ├── llm/
│   │   └── run-ai.sh
│   │
│   ├── extract_semgrep.py
│   ├── extract_codeql.py
│   ├── extract_trivy.py
│   ├── extract_zap.py
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
