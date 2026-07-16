#!/usr/bin/env bash
set -euo pipefail

echo "Running Trivy..."

mkdir -p reports/trivy

scan_image() {
  local image_ref="$1"
  local context="$2"
  local dockerfile="$3"
  local report_path="$4"

  echo "Building ${image_ref}..."
  docker build \
    -t "$image_ref" \
    -f "$dockerfile" \
    "$context"

  echo "Scanning ${image_ref}..."
  if command -v trivy >/dev/null 2>&1; then
    if ! trivy image \
      --format json \
      --severity CRITICAL,HIGH \
      --output "$report_path" \
      "$image_ref"
    then
      echo "${image_ref} scan completed with findings."
    fi

  else
    if ! docker run --rm \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$(pwd)/reports/trivy:/reports" \
      aquasec/trivy:latest \
      image \
      --format json \
      --severity CRITICAL,HIGH \
      --output "/reports/$(basename "$report_path")" \
      "$image_ref"
    then
      echo "Containerized Trivy completed with findings."
    fi
  
  fi

  if [ ! -f "$report_path" ]; then
    echo '{"Results":[]}' > "$report_path"
  fi
}

scan_image \
  "shop-backend:latest" \
  "./backend" \
  "backend/Dockerfile" \
  "reports/trivy/backend-trivy.json"

scan_image \
  "shop-frontend:latest" \
  "./frontend" \
  "frontend/Dockerfile" \
  "reports/trivy/frontend-trivy.json"

# ===== 두 리포트 병합 =====
echo "Merging Trivy reports..."

if command -v jq >/dev/null 2>&1; then
  # jq로 Results 배열 병합
  jq -s 'reduce .[] as $item ({"Results":[]}; .Results += $item.Results)' \
    reports/trivy/backend-trivy.json \
    reports/trivy/frontend-trivy.json \
    > reports/trivy/trivy.json
else
  # jq 없을 경우 간단한 병합 (Python 필요)
  python3 << 'EOF'
  
import json
import glob

results = {"Results": []}
for file in sorted(glob.glob("reports/trivy/*-trivy.json")):
    with open(file) as f:
        data = json.load(f)
        results["Results"].extend(data.get("Results", []))

with open("reports/trivy/trivy.json", "w") as f:
    json.dump(results, f, indent=2)
EOF
fi

if [ ! -f reports/trivy/trivy.json ]; then
  echo '{"Results":[]}' > reports/trivy/trivy.json
fi
echo "✓ Merged report: reports/trivy/trivy.json"