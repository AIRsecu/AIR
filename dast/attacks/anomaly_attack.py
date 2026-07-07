#!/usr/bin/env python3
"""
이상탐지 공격 스크립트 (4xx Scan / Anomaly Scan) (stdlib only)

대상: GET /api/v1/no-such-endpoint (비존재 경로 — 비인증, 404 유발)
     GET /api/v1/health (격리 후 차단 확인용 — 비인증)

BURST_4XX=20, WINDOW_MS=10s: 21회 이상 4xx 응답이 발생하면 anomaly.detection 이 해당 IP 를
격리하고 IncidentService 가 air.shield 를 즉시 자동 활성화한다.
(ANOMALY_SCAN 은 TYPE_TO_DEFENSE 미등록 → AIR_SHIELD 폴백 활성화)

벡터: 4xx Scan (ANOMALY_SCAN)
  - 비존재 경로 25회 요청 → IP 격리 + air.shield 자동 ON → /api/v1/health 재요청으로 차단 여부 판정
  - DEFENDED: anomaly.detection=ON(기본값) → 탐지 즉시 air.shield 자동 활성 → 후속 요청 429
  - VULNERABLE: anomaly.detection=OFF → 탐지 자체 없음 → 후속 요청 200

사용:
  python anomaly_attack.py --base http://localhost:8081

종료코드: 공격 성공(취약)=1, 방어됨=0
"""
import argparse
import sys
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

SCAN_N = 25              # BURST_4XX=20 을 넉넉히 초과 (21번째에 격리)
SCAN_PATH = "/api/v1/no-such-endpoint"
PROBE_PATH = "/api/v1/health"


def get(base, path):
    url = base.rstrip("/") + path
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read()
            return r.status
    except urllib.error.HTTPError as e:
        e.read()
        return e.code
    except urllib.error.URLError as e:
        raise SystemExit(f"[!] 요청 실패(GET {path}): {e.reason}")


def run(base):
    print(f"[>] {SCAN_PATH} 로 {SCAN_N}회 요청 (BURST_4XX=20 초과 → IP 격리 유도)")
    codes = {}
    for _ in range(SCAN_N):
        st = get(base, SCAN_PATH)
        codes[st] = codes.get(st, 0) + 1
    print(f"[<] 스캔 응답 분포: {codes}")

    print(f"[>] 격리 후 정상 경로 재요청: GET {PROBE_PATH}")
    probe_st = get(base, PROBE_PATH)
    print(f"[<] 프로브 응답: HTTP {probe_st}")

    if probe_st == 429:
        print("[RESULT] DEFENDED — 격리 IP 차단됨 (air.shield 작동)")
        return 0
    print("[RESULT] VULNERABLE — 격리 후에도 요청 통과 (air.shield 비활성)")
    return 1


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:8081")
    args = p.parse_args()
    raise SystemExit(run(args.base))
