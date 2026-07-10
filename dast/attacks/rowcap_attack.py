#!/usr/bin/env python3
"""
Bulk Data Harvesting 공격 스크립트 (대량 데이터 덤프) (stdlib only)

대상: GET /api/v1/tenants/{tenantId}/products
상품 250개(ROW_CAP=200 초과)를 생성한 뒤 일괄 조회해 반환 건수로 판정한다.
invariant.row-cap ON 이면 상위 200개만 절단해 반환한다.

사용:
  python rowcap_attack.py --base http://localhost:8081 --admin-user <super_admin> --admin-pass <pw>

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

PRODUCT_N = 250    # ROW_CAP=200 을 넉넉히 초과


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


def prepare(base, token):
    suffix = f"{int(time.time())}{random.randint(100, 999)}"
    st, j = call(base, "POST", "/api/v1/tenants", token,
                 {"name": f"dast-rowcap-{suffix}", "slug": f"dast-rowcap-{suffix}"})
    if st not in (200, 201) or not j or not j.get("data"):
        raise SystemExit(f"[!] 테넌트 생성 실패: {st} {j}")
    return j["data"]["id"]


def run(base, admin_user, admin_pass):
    token = login(base, admin_user, admin_pass)
    tid = prepare(base, token)
    print(f"[*] 준비 완료: tenant={tid}")

    print(f"[>] 상품 {PRODUCT_N}개 생성 중 (ROW_CAP=200 초과)...")
    for i in range(PRODUCT_N):
        st, j = call(base, "POST", f"/api/v1/tenants/{tid}/products", token,
                     {"name": f"dast-bulk-{i:03d}", "price": 100, "stock": 1})
        if st not in (200, 201):
            raise SystemExit(f"[!] 상품 생성 실패({i}): {st} {j}")
        if (i + 1) % 50 == 0:
            print(f"[*]   {i + 1}/{PRODUCT_N} 완료")
        time.sleep(0.35)  # DDoS RATE_LIMIT(30/10s) 초과 방지
    print(f"[*] {PRODUCT_N}개 생성 완료")

    print(f"[>] 일괄 조회: GET /api/v1/tenants/{tid}/products")
    st, j = call(base, "GET", f"/api/v1/tenants/{tid}/products", token)
    if st != 200 or not j or j.get("data") is None:
        raise SystemExit(f"[!] 상품 목록 조회 실패: {st} {j}")
    count = len(j["data"])
    print(f"[<] 반환된 상품 수: {count}개")

    if count > 200:
        print(f"[RESULT] VULNERABLE — {count}개 전량 반환됨 (ROW_CAP 미적용, {count - 200}개 초과)")
        return 1
    print(f"[RESULT] DEFENDED — {count}개로 절단됨 (invariant.row-cap=200 적용)")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:8081")
    p.add_argument("--admin-user", required=True)
    p.add_argument("--admin-pass", required=True)
    args = p.parse_args()
    raise SystemExit(run(args.base, args.admin_user, args.admin_pass))
