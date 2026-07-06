#!/usr/bin/env bash
set -euo pipefail

echo "Generating security summary..."

mkdir -p reports/summary

test -f reports/semgrep/semgrep.json || {
  echo "ERROR: Semgrep report not found"
  exit 1
}
test -f reports/trivy/trivy.json || {
  echo "ERROR: Trivy report not found"
  exit 1
}
test -f reports/zap/zap-report.json || {
  echo "ERROR: ZAP report not found"
  exit 1
}

poetry run python scripts/generate_summary.py

echo "✓ Security summary generated"