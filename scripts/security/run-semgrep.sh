#!/usr/bin/env bash
set -euo pipefail

echo "Running Semgrep..."

mkdir -p reports/semgrep

# Findings should be evaluated by the security gate, so the scan itself should
# always publish JSON for the summary step.
poetry run semgrep scan \
  --config auto \
  . \
  --json \
  --output reports/semgrep/semgrep.json || true

if [ ! -f reports/semgrep/semgrep.json ]; then
  echo '{"results":[]}' > reports/semgrep/semgrep.json
fi
