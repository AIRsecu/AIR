import json
from pathlib import Path

SEMGREP_PATH = Path("reports/semgrep/semgrep.json")
TRIVY_PATH = Path("reports/trivy/trivy.json")
OUTPUT_PATH = Path("reports/summary/sec-summary.json")

summary = {
    "semgrep_findings": 0,
    "trivy_critical": 0,
    "trivy_high": 0,
}

if SEMGREP_PATH.exists():
    with open(SEMGREP_PATH) as f:
        semgrep_data = json.load(f)

    summary["semgrep_findings"] = len(
        semgrep_data.get("results", [])
    )

if TRIVY_PATH.exists():
    with open(TRIVY_PATH) as f:
        trivy_data = json.load(f)

    for result in trivy_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):

            severity = vuln.get("Severity")

            if severity == "CRITICAL":
                summary["trivy_critical"] += 1

            elif severity == "HIGH":
                summary["trivy_high"] += 1


OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

with open(OUTPUT_PATH, "w") as f:
    json.dump(summary, f, indent=2)

print("Security summary generated.")