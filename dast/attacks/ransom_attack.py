#!/usr/bin/env python3
"""
Ransomware-유사 공격 스크립트 (Mass Delete) (stdlib only)

대상: DELETE /api/v1/tenants/{tid}/products/{pid}
10초 창(WINDOW_MS=10s) 내 5건(MASSDELETE_LIMIT) 초과 연속 삭제로
ransom.massdelete-guard 자동 활성화를 유도한다.
DELETE 차단 여부로 VULNERABLE/DEFENDED 를 판정한다.

사용:
  python ransom_attack.py --base http://localhost:8081 --admin-user <super_admin> --admin-pass <pw>

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

DELETE_N = 10    # MASSDELETE_LIMIT(5) 을 넉넉히 초과


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
                 {"name": f"dast-ransom-{suffix}", "slug": f"dast-ransom-{suffix}"})
    if st not in (200, 201):
        raise SystemExit(f"[!] 테넌트 생성 실패: {st} {j}")
    tid = j["data"]["id"]

    pids = []
    for i in range(DELETE_N):
        st, j = call(base, "POST", f"/api/v1/tenants/{tid}/products", admin_tok,
                     {"name": f"dast-target-{i}", "price": 1000, "stock": 1})
        if st not in (200, 201):
            raise SystemExit(f"[!] 상품 생성 실패({i}): {st} {j}")
        pids.append(j["data"]["id"])

    return tid, pids


def run(base, admin_user, admin_pass):
    admin_tok = login(base, admin_user, admin_pass)
    tid, pids = prepare(base, admin_tok)
    print(f"[*] 준비 완료: tenant={tid}, 상품 {len(pids)}개 생성")

    print(f"[>] {len(pids)}건 연속 DELETE (MASSDELETE_LIMIT=5 초과)")
    codes = {}
    blocked = 0
    deleted = 0
    for pid in pids:
        st, _ = call(base, "DELETE", f"/api/v1/tenants/{tid}/products/{pid}", admin_tok)
        codes[st] = codes.get(st, 0) + 1
        if st in (200, 204):
            deleted += 1
        elif st in (429, 403):
            blocked += 1
    print(f"[<] 응답 분포: {codes}")
    print(f"[*] 삭제 성공: {deleted}건, 차단: {blocked}건")

    if blocked > 0:
        print(f"[RESULT] DEFENDED - {blocked}건 차단 (대량삭제 방어 작동)")
        return 0
    print(f"[RESULT] VULNERABLE - {deleted}건 전부 삭제됨 (대량삭제 무제한)")
    return 1


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:8081")
    p.add_argument("--admin-user", required=True)
    p.add_argument("--admin-pass", required=True)
    args = p.parse_args()
    raise SystemExit(run(args.base, args.admin_user, args.admin_pass))
