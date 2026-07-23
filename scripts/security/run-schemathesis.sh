#!/bin/bash

set -e

SCHEMA_PATH="docs/openapi/openapi.json"
BASE_URL="${SCHEMATHESIS_BASE_URL:-http://localhost:8080}"
REPORT_DIR="reports/openapi"

mkdir -p "$REPORT_DIR"

echo "========== Schemathesis =========="
echo "Schema : $SCHEMA_PATH"
echo "Base URL : $BASE_URL"

schemathesis run \
  "$SCHEMA_PATH" \
  --url "$BASE_URL" \
  --report-junit-path "$REPORT_DIR/schemathesis-report.xml" \
  | tee "$REPORT_DIR/schemathesis.log"

echo "Convert XML to JSON..."

python3 scripts/parse_schemathesis.py

echo "Schemathesis finished."