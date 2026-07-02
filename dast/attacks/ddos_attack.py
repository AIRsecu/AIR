#!/usr/bin/env python3
"""
DDoS 공격 스크립트 (Rate Flood) (stdlib only)

대상: GET /api/v1/health (비인증 엔드포인트)
10초 창(WINDOW_MS=10s) 내 30건(RATE_LIMIT) 초과 요청으로
ddos.rate-guard 자동 활성화를 유도한다.
429 응답 발생 여부로 VULNERABLE/DEFENDED 를 판정한다.

사용:
  python ddos_attack.py --base http://localhost:8081

종료코드: 공격 성공(취약)=1, 방어됨=0
"""
import argparse
import sys
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

BURST = 60       # RATE_LIMIT(30) 을 넉넉히 초과
TARGET = "/api/v1/health"


def call(base, path):
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
    print(f"[>] {TARGET} 로 {BURST}회 연속 요청 (RATE_LIMIT=30 초과)")
    codes = {}
    blocked = 0
    for _ in range(BURST):
        st = call(base, TARGET)
        codes[st] = codes.get(st, 0) + 1
        if st == 429:
            blocked += 1
    print(f"[<] 상태코드 분포: {codes}")

    if blocked > 0:
        print(f"[RESULT] DEFENDED - {blocked}건 429 차단 (레이트리밋 적용)")
        return 0
    print(f"[RESULT] VULNERABLE - 전체 {BURST}건 통과 (레이트리밋 없음)")
    return 1


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:8081")
    args = p.parse_args()
    raise SystemExit(run(args.base))
