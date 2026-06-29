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

critical_threshold = policy.get("trivy_critical", 1)
high_threshold = policy.get("trivy_high", 5)
semgrep_threshold = policy.get("semgrep_findings", 3)

if trivy_critical >= critical_threshold:
    print(
        f"Critical vulnerabilities found: "
        f"{trivy_critical}"
    )
    sys.exit(1)

if trivy_high >= high_threshold:
    print(
        f"Too many HIGH vulnerabilities: "
        f"{trivy_high}"
    )
    sys.exit(1)

if semgrep_findings >= semgrep_threshold:
    print(
        f"Too many Semgrep findings: "
        f"{semgrep_findings}"
    )
    sys.exit(1)

print(json.dumps(policy, indent=2))
print("Security gate passed.")

