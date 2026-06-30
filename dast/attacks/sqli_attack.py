#!/usr/bin/env python3
"""
SQL Injection 공격 스크립트 (stdlib only)

대상: GET /api/v1/tenants/{tid}/products/search?q=
무관한 검색어(0건 기대)와 인젝션 검색어(' OR '1'='1)의 결과 건수를 비교해
필터 우회 여부를 판별한다.

사용:
  python sqli_attack.py --base http://localhost:8081 --admin-user admin --admin-pass <pw>

종료코드: 공격 성공(취약)=1, 방어됨=0
"""
import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")


def call(base, method, path, token=None, body=None):
    url = base.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        return e.code, (json.loads(raw) if raw else None)
    except urllib.error.URLError as e:
        raise SystemExit(f"[!] 요청 실패({method} {path}): {e.reason}")


def login(base, username, password):
    st, j = call(base, "POST", "/api/v1/auth/login",
                 body={"username": username, "password": password})
    if st != 200 or not j or not j.get("data"):
        raise SystemExit(f"[!] 로그인 실패({username}): {st} {j}")
    return j["data"]["accessToken"]


def prepare(base, admin_tok):
    suffix = f"{int(time.time())}{random.randint(100, 999)}"
    st, j = call(base, "POST", "/api/v1/tenants", admin_tok,
                 {"name": f"dast-sqli-{suffix}", "slug": f"dast-sqli-{suffix}"})
    if st not in (200, 201):
        raise SystemExit(f"[!] 테넌트 생성 실패: {st} {j}")
    tid = j["data"]["id"]
    st, j = call(base, "POST", f"/api/v1/tenants/{tid}/products", admin_tok,
                 {"name": "dast-target", "price": 1000, "stock": 1})
    if st not in (200, 201):
        raise SystemExit(f"[!] 상품 생성 실패: {st} {j}")
    return tid


def search(base, tid, token, q):
    path = f"/api/v1/tenants/{tid}/products/search?q=" + urllib.parse.quote(q, safe="")
    st, j = call(base, "GET", path, token)
    rows = (j or {}).get("data") or []
    return st, rows


def run(base, admin_user, admin_pass):
    admin_tok = login(base, admin_user, admin_pass)
    tid = prepare(base, admin_tok)

    benign = f"zzz_nomatch_{int(time.time())}"
    st_b, rows_b = search(base, tid, admin_tok, benign)
    print(f"[*] 기준선 검색 q='{benign}' -> HTTP {st_b}, {len(rows_b)}건 (정상=0)")

    payload = "' OR '1'='1"
    st_i, rows_i = search(base, tid, admin_tok, payload)
    print(f"[>] 인젝션 검색 q=\"{payload}\" -> HTTP {st_i}, {len(rows_i)}건")

    if st_i == 200 and len(rows_i) > len(rows_b):
        print(f"[RESULT] VULNERABLE - 인젝션으로 필터 우회 (기준선 {len(rows_b)}건 -> {len(rows_i)}건)")
        return 1
    print("[RESULT] DEFENDED - 인젝션 무력화 (기준선 대비 증가 없음/차단)")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:8081")
    p.add_argument("--admin-user", required=True)
    p.add_argument("--admin-pass", required=True)
    args = p.parse_args()
    raise SystemExit(run(args.base, args.admin_user, args.admin_pass))
