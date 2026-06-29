# Security Policy

## Policy Source

policy/security_policy.json

---

## Current Thresholds

| Scanner | Condition | Result |
|---|---|---|
| Trivy Critical | >= 1 | Fail |
| Trivy High | >= 5 | Fail |
| Semgrep Findings | >= 3 | Fail |
| ZAP High | >= 1 | Fail |
| ZAP Medium | >= 5 | Fail |

---

## Security Decision Flow

Integrated Summary
↓
Policy Evaluation
↓
Pass / Fail