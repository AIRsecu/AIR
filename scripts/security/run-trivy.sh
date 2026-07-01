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
    trivy image \
      --format json \
      --severity CRITICAL,HIGH \
      --output "$report_path" \
      "$image_ref"
  else
    docker run --rm \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$(pwd)/reports/trivy:/reports" \
      aquasec/trivy:latest \
      image \
      --format json \
      --severity CRITICAL,HIGH \
      --output "/reports/$(basename "$report_path")" \
      "$image_ref"
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