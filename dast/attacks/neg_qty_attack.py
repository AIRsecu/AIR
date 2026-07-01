#!/usr/bin/env python3
"""
Negative Quantity Attack (Business Logic Vulnerability) 공격 스크립트 (stdlib only)

대상: POST /api/v1/tenants/{tid}/orders
음수 수량(quantity < 0)으로 주문하면 total 이 음수가 되어,
잔액 차감 조건(balance >= amount)이 항상 통과하고 잔액이 오히려 증가한다.
공격 전후 잔액을 비교해 VULNERABLE/DEFENDED 를 판정한다.

사용:
  python neg_qty_attack.py --base http://localhost:8081 --admin-user <super_admin> --admin-pass <pw>

참고: 고객 계정 생성에 super_admin 권한이 필요하므로 super_admin 계정을 사용해야 한다.

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


def prepare(base, admin_tok):
    suffix = f"{int(time.time())}{random.randint(100, 999)}"
    st, j = call(base, "POST", "/api/v1/tenants", admin_tok,
                 {"name": f"dast-negqty-{suffix}", "slug": f"dast-negqty-{suffix}"})
    if st not in (200, 201):
        raise SystemExit(f"[!] 테넌트 생성 실패: {st} {j}")
    tid = j["data"]["id"]

    st, j = call(base, "POST", f"/api/v1/tenants/{tid}/products", admin_tok,
                 {"name": "dast-target", "price": 5000, "stock": 100})
    if st not in (200, 201):
        raise SystemExit(f"[!] 상품 생성 실패: {st} {j}")
    pid = j["data"]["id"]

    cu = f"dast-negqty-{suffix}"
    cp = "Dast@NegQty2026!"
    st, j = call(base, "POST", "/api/v1/users", admin_tok,
                 {"username": cu, "password": cp, "role": "customer",
                  "displayName": "dast-attacker", "tenantId": tid})
    if st not in (200, 201):
        raise SystemExit(f"[!] 고객 생성 실패: {st} {j}")

    return tid, pid, cu, cp


def get_balance(base, token):
    st, j = call(base, "GET", "/api/v1/users/me", token)
    return (j or {}).get("data", {}).get("balance")


def run(base, admin_user, admin_pass):
    admin_tok = login(base, admin_user, admin_pass)
    tid, pid, cu, cp = prepare(base, admin_tok)
    print(f"[*] 준비 완료: tenant={tid}, product={pid}, customer={cu}")

    cust_tok = login(base, cu, cp)
    before = get_balance(base, cust_tok)
    print(f"[*] 공격 전 잔액: {before}")

    st, j = call(base, "POST", f"/api/v1/tenants/{tid}/orders", cust_tok,
                 {"items": [{"productId": pid, "quantity": -100}]})
    print(f"[>] 주문 요청 quantity=-100 (단가 5000) -> HTTP {st}")

    after = get_balance(base, cust_tok)
    print(f"[*] 공격 후 잔액: {after}")

    if after is not None and before is not None and after > before:
        print(f"[RESULT] VULNERABLE - 잔액 {before} -> {after} (+{after - before})")
        return 1
    print(f"[RESULT] DEFENDED - 잔액 불변 또는 주문 차단 (HTTP {st})")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:8081")
    p.add_argument("--admin-user", required=True)
    p.add_argument("--admin-pass", required=True)
    args = p.parse_args()
    raise SystemExit(run(args.base, args.admin_user, args.admin_pass))
