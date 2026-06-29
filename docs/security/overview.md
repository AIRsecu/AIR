# DevSecOps Security Pipeline

## Security Components

| Tool | Type | Purpose |
|---|---|---|
| Semgrep | SAST | Static code analysis |
| Trivy | SCA / Container | Dependency and image scan |
| ZAP | DAST | Runtime web vulnerability scan |

---

## Pipeline Flow

Developer Push
↓
GitHub Actions
↓
Semgrep Scan
↓
Trivy Scan
↓
ZAP Scan
↓
Integrated Summary Generation
↓
Centralized Security Gate
↓
Pass / Fail

---

## Report Structure

reports/
├── semgrep/
├── trivy/
├── zap/
└── summary/

---

## Generated Reports

| Scanner | Output |
|---|---|
| Semgrep | semgrep.json |
| Trivy | trivy.json |
| ZAP | zap-report.json |
| Summary | sec-summary.json |

---

## Summary Generator

scripts/generate_summary.py

---

## Security Gate

policy/security_gate.py