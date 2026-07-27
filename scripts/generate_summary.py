import json
from pathlib import Path

SEMGREP_PATH = Path("reports/semgrep/semgrep.json")
TRIVY_DIR = Path("reports/trivy")
ZAP_PATH = Path("reports/zap/zap-report.json")
OUTPUT_PATH = Path("reports/summary/sec-summary.json")

print("Generating integrated security summary...")

summary = {
    "semgrep_findings": 0,
    "trivy_critical": 0,
    "trivy_high": 0,
    "zap_high": 0,
    "zap_medium": 0,
}

if SEMGREP_PATH.exists():
    with open(SEMGREP_PATH) as f:
        semgrep_data = json.load(f)

    summary["semgrep_findings"] = len(
        semgrep_data.get("results", [])
    )

for trivy_path in sorted(TRIVY_DIR.glob("*.json")):
    with open(trivy_path) as f:
        trivy_data = json.load(f)

    for result in trivy_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            severity = vuln.get("Severity")

            if severity == "CRITICAL":
                summary["trivy_critical"] += 1
            elif severity == "HIGH":
                summary["trivy_high"] += 1

if ZAP_PATH.exists():
    with open(ZAP_PATH) as f:
        zap_data = json.load(f)

    sites = zap_data.get("site", [])

    if sites:
        for alert in sites[0].get("alerts", [], ):
            risk = alert.get("riskdesc", "", )
            if "High" in risk:
                summary["zap_high"] += 1
            elif "Medium" in risk:
                summary["zap_medium"] += 1

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

with open(OUTPUT_PATH, "w") as f:
    json.dump(summary, f, indent=2)

print("Security summary generated.")