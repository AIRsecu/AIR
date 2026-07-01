#!/usr/bin/env bash
set -euo pipefail

echo "Generating security summary..."

mkdir -p reports/summary

test -f reports/semgrep/semgrep.json
test -f reports/trivy/trivy.json
test -f reports/zap/zap-report.json

poetry run python scripts/generate_summary.py
poetry run python policy/security_gate.py
