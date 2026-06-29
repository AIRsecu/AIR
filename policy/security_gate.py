import json
import sys
from pathlib import Path

SUMMARY_PATH = Path("reports/summary/sec-summary.json")
POLICY_PATH = Path("policy/security_policy.json")

if not SUMMARY_PATH.exists():
    print("Summary report not found.")
    sys.exit(1)

with open(SUMMARY_PATH) as f:
    summary = json.load(f)

with open(POLICY_PATH) as f:
    policy = json.load(f)

semgrep_findings = summary.get("semgrep_findings", 0)
trivy_critical = summary.get("trivy_critical", 0)
trivy_high = summary.get("trivy_high", 0)
zap_high = summary.get("zap_high", 0)
zap_medium = summary.get("zap_medium", 0)

critical_threshold = policy.get("trivy_critical", 1)
high_threshold = policy.get("trivy_high", 5)
semgrep_threshold = policy.get("semgrep_findings", 3)
zap_high_threshold = policy.get("zap_high", 1)
zap_medium_threshold = policy.get("zap_medium", 5)

failures = []

if trivy_critical >= critical_threshold:
    failures.append(
        f"Critical vulnerabilities found: "
        f"{trivy_critical}"
    )

if trivy_high >= high_threshold:
    failures.append(
        f"Too many HIGH vulnerabilities: "
        f"{trivy_high}"
    )

if semgrep_findings >= semgrep_threshold:
    failures.append(
        f"Too many Semgrep findings: "
        f"{semgrep_findings}"
    )

if zap_high >= zap_high_threshold:
    failures.append(
        f"Too many ZAP HIGH alerts: "
        f"{zap_high}"
    )

if zap_medium >= zap_medium_threshold:
    failures.append(
        f"Too many ZAP MEDIUM alerts: "
        f"{zap_medium}"
    )

print(json.dumps(policy, indent=2))
if failures:
    print("Security gate failed:")
    for failure in failures:
        print(f"- {failure}")
    sys.exit(1)
print("Security gate passed.")

