import json
import sys
from pathlib import Path

SUMMARY_PATH = Path("reports/summary/sec-summary.json")

if not SUMMARY_PATH.exists():
    print("Summary report not found.")
    sys.exit(1)

with open(SUMMARY_PATH) as f:
    summary = json.load(f)

critical = summary.get("trivy_critical", 0)

if critical > 0:
    print(f"Critical vulnerabilities found: {critical}")
    sys.exit(1)

print("Security gate passed.")