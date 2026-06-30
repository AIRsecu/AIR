import json
import sys
from pathlib import Path

SUMMARY_PATH = Path("reports/summary/sec-summary.json")
POLICY_PATH = Path("policy/security_policy.json")

CHECKS = [
    ("trivy_critical", "Critical vulnerabilities found"),
    ("trivy_high", "Too many HIGH vulnerabilities"),
    ("semgrep_findings", "Too many Semgrep findings"),
    ("zap_high", "Too many ZAP HIGH alerts"),
    ("zap_medium", "Too many ZAP MEDIUM alerts"),
]


def load_json(path: Path, label: str) -> dict:
    if not path.exists():
        print(f"{label} not found: {path}")
        sys.exit(1)

    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"{label} is not valid JSON: {path} ({e})")
        sys.exit(1)

def read_count(data: dict, key: str, default: int = 0) -> int:
    value = data.get(key, default)

    try:
        return int(value)
    except (TypeError, ValueError):
        print(f"Invalid numeric value for '{key}': {value!r}")
        sys.exit(1)

def main() -> int:
    summary = load_json(SUMMARY_PATH, "Summary report")
    policy = load_json(POLICY_PATH, "Security policy")
    failures = []

    print("Security gate results:")

    for key, message in CHECKS:
        actual = read_count(summary, key, 0)
        threshold = read_count(policy, key)

        status = "FAIL" if actual >= threshold else "PASS"
        print(f"- {key}: {actual} / threshold {threshold} [{status}]")

        if actual >= threshold:
            failures.append(
                f"{message}: {actual} (threshold: {threshold})"
            )

    if failures:
        print("Security gate failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Security gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())