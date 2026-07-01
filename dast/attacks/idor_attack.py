#!/usr/bin/env python3
"""
IDOR (Insecure Direct Object Reference) 공격 스크립트 (stdlib only)

대상: GET /api/v1/tenants/{tid}/orders/{oid}
피해자(custA)가 생성한 주문 ID를 공격자(custB)가 직접 조회해
소유자 검증 없이 타인의 주문 데이터가 반환되는지 판정한다.

사용:
  python idor_attack.py --base http://localhost:8081 --admin-user <super_admin> --admin-pass <pw>

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
                 {"name": f"dast-idor-{suffix}", "slug": f"dast-idor-{suffix}"})
    if st not in (200, 201):
        raise SystemExit(f"[!] 테넌트 생성 실패: {st} {j}")
    tid = j["data"]["id"]

    st, j = call(base, "POST", f"/api/v1/tenants/{tid}/products", admin_tok,
                 {"name": "dast-target", "price": 1000, "stock": 10})
    if st not in (200, 201):
        raise SystemExit(f"[!] 상품 생성 실패: {st} {j}")
    pid = j["data"]["id"]

    ua, pa = f"dast-idor-a-{suffix}", "Dast@IdorA2026!"
    st, j = call(base, "POST", "/api/v1/users", admin_tok,
                 {"username": ua, "password": pa, "role": "customer",
                  "displayName": "dast-victim", "tenantId": tid})
    if st not in (200, 201):
        raise SystemExit(f"[!] 피해자 계정 생성 실패: {st} {j}")

    ub, pb = f"dast-idor-b-{suffix}", "Dast@IdorB2026!"
    st, j = call(base, "POST", "/api/v1/users", admin_tok,
                 {"username": ub, "password": pb, "role": "customer",
                  "displayName": "dast-attacker", "tenantId": tid})
    if st not in (200, 201):
        raise SystemExit(f"[!] 공격자 계정 생성 실패: {st} {j}")

    return tid, pid, ua, pa, ub, pb


def run(base, admin_user, admin_pass):
    admin_tok = login(base, admin_user, admin_pass)
    tid, pid, ua, pa, ub, pb = prepare(base, admin_tok)
    print(f"[*] 준비 완료: tenant={tid}, product={pid}")
    print(f"[*] 피해자={ua}, 공격자={ub}")

    # 피해자 잔액 충전 (충전 요청 → 관리자 승인)
    a_tok = login(base, ua, pa)
    st, j = call(base, "POST", f"/api/v1/tenants/{tid}/charge-requests", a_tok,
                 {"amount": 10000})
    if st not in (200, 201):
        raise SystemExit(f"[!] 충전 요청 실패: {st} {j}")
    cid = j["data"]["id"]

    st, _ = call(base, "POST", f"/api/v1/tenants/{tid}/charge-requests/{cid}/approve",
                 admin_tok)
    if st not in (200, 201):
        raise SystemExit(f"[!] 충전 승인 실패: {st}")
    print(f"[*] 피해자 잔액 충전 완료 (10,000원)")

    # 피해자 주문 생성
    st, j = call(base, "POST", f"/api/v1/tenants/{tid}/orders", a_tok,
                 {"items": [{"productId": pid, "quantity": 1}]})
    if st not in (200, 201):
        raise SystemExit(f"[!] 주문 생성 실패: {st} {j}")
    oid = j["data"]["id"]
    print(f"[*] 피해자 주문 생성: order={oid}")

    # 공격자가 피해자 주문 ID를 직접 조회
    b_tok = login(base, ub, pb)
    print(f"[>] 공격자가 피해자 주문 직접 조회: GET /orders/{oid}")
    st, j = call(base, "GET", f"/api/v1/tenants/{tid}/orders/{oid}", b_tok)
    got = (j or {}).get("data", {}).get("id") if j else None
    print(f"[<] 응답: HTTP {st}, data.id={got}")

    if st == 200 and got == oid:
        print("[RESULT] VULNERABLE - 타 고객 주문이 그대로 노출됨 (IDOR)")
        return 1
    print(f"[RESULT] DEFENDED - 소유자 검증으로 차단됨 (HTTP {st})")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:8081")
    p.add_argument("--admin-user", required=True)
    p.add_argument("--admin-pass", required=True)
    args = p.parse_args()
    raise SystemExit(run(args.base, args.admin_user, args.admin_pass))
