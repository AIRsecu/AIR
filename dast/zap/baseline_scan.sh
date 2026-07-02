#!/usr/bin/env bash
# ZAP Baseline Scan 실행 스크립트
# 사용: ./baseline_scan.sh [TARGET_URL]
# TARGET_URL 기본값: http://host.docker.internal:8081
#
# Windows Docker Desktop 환경에서는 호스트 디렉터리를 zap 컨테이너에 직접 bind mount하면
# 쓰기 권한이 없어 리포트를 생성할 수 없다. 그래서 named volume을 중간에 두고,
# 스캔이 끝나면 docker cp로 호스트에 리포트를 꺼낸다.
set -euo pipefail

TARGET="${1:-http://host.docker.internal:8081}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/reports"
VOLUME="air-attack-zap-wrk"
IMAGE="ghcr.io/zaproxy/zaproxy:stable"

mkdir -p "$DIR"
docker volume create "$VOLUME" >/dev/null

# named volume은 기본적으로 root 소유로 생성되므로, zap 컨테이너 기본 사용자(uid 1000)가
# 쓸 수 있도록 최초 1회 소유권을 맞추고, 이전 실행의 리포트가 남아 결과를 속이지 않도록 비워둔다.
docker run --rm -u root -v "$VOLUME:/zap/wrk/:rw" "$IMAGE" \
  sh -c "rm -f /zap/wrk/baseline-report.* && chown -R 1000:1000 /zap/wrk"

# zap-baseline.py는 FAIL 등급 발견 시 비정상 종료 코드를 낼 수 있다(-I는 WARN만 무시).
# set -e로 즉시 죽으면 리포트를 못 꺼내므로, 종료 코드를 잡아두고 추출은 항상 진행한다.
set +e
docker run --rm -v "$VOLUME:/zap/wrk/:rw" "$IMAGE" \
  zap-baseline.py \
  -t "$TARGET" \
  -r baseline-report.html \
  -J baseline-report.json \
  -I
SCAN_EXIT=$?
set -e

# docker cp가 중간에 실패해도(리포트 파일이 끝내 안 생긴 경우 등) 추출용 컨테이너가
# 남지 않도록 trap으로 무조건 정리한다.
CID=""
cleanup() { [ -n "$CID" ] && docker rm -f "$CID" >/dev/null 2>&1; return 0; }
trap cleanup EXIT

# docker cp의 호스트 측 목적지는 네이티브 Windows 경로여야 하므로 cygpath로 변환한다.
HOST_DIR="$(command -v cygpath >/dev/null 2>&1 && cygpath -w "$DIR" || echo "$DIR")"
CID=$(docker create -v "$VOLUME:/zap/wrk/:rw" "$IMAGE" true)
docker cp "$CID:/zap/wrk/baseline-report.html" "$HOST_DIR/baseline-report.html"
docker cp "$CID:/zap/wrk/baseline-report.json" "$HOST_DIR/baseline-report.json"

echo "리포트 생성 위치: $DIR (스캔 종료 코드: $SCAN_EXIT)"
exit "$SCAN_EXIT"
