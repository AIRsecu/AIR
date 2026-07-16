#!/usr/bin/env bash
set -euo pipefail

echo "Running Semgrep..."

mkdir -p reports/semgrep

# Findings should be evaluated by the security gate, so the scan itself should
# always publish JSON for the summary step.
if ! semgrep scan \
  --config "p/java" \
  --config "p/jwt" \
  --config "p/javascript" \
  --config "p/owasp-top-ten" \
  --config "p/secrets" \
  --exclude ".github/**" \
  --exclude "docs/**" \
  --exclude "frontend/css/**" \
  --exclude "**/*.sql" \
  --exclude "scripts/**" \
  --exclude "policy/**" \
  . \
  --json \
  --output reports/semgrep/semgrep.json
then
  echo "Semgrep completed with findings or warnings."
fi
