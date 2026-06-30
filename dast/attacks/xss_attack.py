#!/usr/bin/env python3
"""
Stored XSS 공격 스크립트 (stdlib only)

대상: POST /api/v1/tenants/{tid}/products (name 필드)
스크립트 태그를 상품명에 저장한 뒤, 다시 조회해 원문 그대로 남아있는지 확인한다.

사용:
  python xss_attack.py --base http://localhost:8081 --admin-user admin --admin-pass <pw>

종료코드: 공격 성공(취약)=1, 방어됨=0
"""
import argparse
import json
import random
import sys
import time
import urllib.error
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


def prepare_tenant(base, admin_tok):
    suffix = f"{int(time.time())}{random.randint(100, 999)}"
    st, j = call(base, "POST", "/api/v1/tenants", admin_tok,
                 {"name": f"dast-xss-{suffix}", "slug": f"dast-xss-{suffix}"})
    if st not in (200, 201):
        raise SystemExit(f"[!] 테넌트 생성 실패: {st} {j}")
    return j["data"]["id"]


def run(base, admin_user, admin_pass):
    admin_tok = login(base, admin_user, admin_pass)
    tid = prepare_tenant(base, admin_tok)

    payload = "<script>alert('air-dast-xss')</script>"
    st, j = call(base, "POST", f"/api/v1/tenants/{tid}/products", admin_tok,
                 {"name": payload, "price": 1000, "stock": 1})
    print(f"[>] 상품 생성(name={payload}) -> HTTP {st}")

    pid = (j or {}).get("data", {}).get("id") if j else None
    if not pid:
        print("[RESULT] DEFENDED - 생성 자체가 차단됨")
        return 0

    st, j = call(base, "GET", f"/api/v1/tenants/{tid}/products/{pid}", admin_tok)
    stored = (j or {}).get("data", {}).get("name", "")
    print(f"[*] 저장된 name: {stored}")

    if "<script" in stored.lower():
        print("[RESULT] VULNERABLE - 스크립트가 원문 그대로 저장됨")
        return 1
    print("[RESULT] DEFENDED - 입력이 이스케이프/제거됨")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:8081")
    p.add_argument("--admin-user", required=True)
    p.add_argument("--admin-pass", required=True)
    args = p.parse_args()
    raise SystemExit(run(args.base, args.admin_user, args.admin_pass))
