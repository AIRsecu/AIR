# DevSecOps CI/CD Demo & Scenarios

## 1. Overview

This document combines both:
- Demo flow (presentation view)
- CI/CD security scenarios (detailed explanation)

---

## 2. Architecture Flow (Demo View)

Developer Push
↓
GitHub Actions Trigger
↓
Semgrep (SAST)
↓
Trivy (SCA / Container Scan)
↓
ZAP (DAST)
↓
Integrated Summary Generator
↓
Security Policy Gate
↓
PASS / FAIL Decision

---

## 3. Scenario 1 — Vulnerable Code (FAIL Case)

### Flow

Push vulnerable code
↓
Semgrep detects issue
↓
Trivy detects vulnerabilities
↓
ZAP detects runtime issues
↓
Summary generated
↓
Security Gate evaluates policy
↓
PIPELINE FAILS

### Result

- Critical or High vulnerabilities detected
- Policy threshold exceeded
- Deployment blocked

---

## 4. Scenario 2 — Secure Code (PASS Case)

### Flow

Developer fixes issues
↓
All scanners pass
↓
Summary generated
↓
Security Gate evaluates policy
↓
PIPELINE PASSES

### Result

- No critical issues
- Below threshold
- Deployment allowed

---

## 5. Key Security Logic

| Scanner | Role |
|--------|------|
| Semgrep | Static code analysis |
| Trivy | Dependency & container scan |
| ZAP | Runtime security testing |

---

## 6. Policy Decision Example

| Metric | Value | Threshold | Result |
|--------|------|----------|--------|
| Trivy Critical | 2 | 1 | FAIL |
| Trivy High | 7 | 5 | FAIL |
| Semgrep Findings | 1 | 3 | PASS |

---

## 7. Core Value of System

- Multi-layer security scanning
- Automated CI/CD enforcement
- Centralized policy-based decision
- Fully automated pipeline blocking