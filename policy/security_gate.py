import json
import sys
from pathlib import Path

SUMMARY_PATH = Path("reports/summary/sec-summary.json")

if not SUMMARY_PATH.exists():
    print("Summary report not found.")
    sys.exit(1)

with open(SUMMARY_PATH) as f:
    summary = json.load(f)

semgrep_findings = summary.get("semgrep_findings", 0)
trivy_critical = summary.get("trivy_critical", 0)
trivy_high = summary.get("trivy_high", 0)

if trivy_critical > 0:
    print(
        f"Critical vulnerabilities found: "
        f"{trivy_critical}"
    )
    sys.exit(1)

if trivy_high >= 5:
    print(
        f"Too many HIGH vulnerabilities: "
        f"{trivy_high}"
    )
    sys.exit(1)

if semgrep_findings >= 3:
    print(
        f"Too many Semgrep findings: "
        f"{semgrep_findings}"
    )
    sys.exit(1)

print("Security gate passed.")

