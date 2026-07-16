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

| 영역              | 내용                        |
| --------------- | ------------------------- |
| CI              | GitHub Actions            |
| SAST            | Semgrep                   |
| Dependency Scan | Trivy                     |
| DAST            | OWASP ZAP                 |
| Reporting       | GitHub Artifact / Summary |

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
