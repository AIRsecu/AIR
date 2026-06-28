#!/usr/bin/env python3
"""
AIR 자율 방어 오케스트레이터 (별도 프로세스).

폐루프:
  /air/incidents 폴링 → 미처리(MITIGATED) 인시던트 → 취약 위치 매핑
  → Claude API 패치 생성(실패 시 템플릿 폴백) → 격리 브랜치 적용
  → 검증(런타임 플래그 OFF로 공격 재현 → 소스 자체로 차단되는지) → 통과 시 커밋(+push)
  → 인시던트 status=PATCHED/FAILED 기록.  실패 시 롤백(런타임 플래그는 유지).

실행 예:
  python responder.py --base http://localhost:8081 --admin-user admin --admin-pass <pw> \
      --repo ~/air-repo --once            # 1회 처리
  python responder.py ... --interval 15   # 상시 폴링
의존성 없음(stdlib). ANTHROPIC_API_KEY 설정 시 LLM 패치, 없으면 템플릿.
"""
import argparse, json, os, subprocess, sys, time, urllib.request, urllib.error
import llm_patcher
from knowledge import VULNS


# ── HTTP ──────────────────────────────────────────────────────
def api(base, method, path, token=None, body=None):
    url = base.rstrip('/') + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header('Content-Type', 'application/json')
    if token:
        req.add_header('Authorization', 'Bearer ' + token)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        return e.code, (json.loads(raw) if raw else None)

def login(base, user, pw):
    st, j = api(base, 'POST', '/api/v1/auth/login', body={'username': user, 'password': pw})
    if st != 200 or not j or not j.get('data'):
        sys.exit(f"[!] super_admin 로그인 실패: {st} {j}")
    return j['data']['accessToken']

def set_status(base, token, inc_id, status, action):
    api(base, 'POST', f'/api/v1/air/incidents/{inc_id}/status?status={status}&action={action}', token)


# ── Stage3: 이상/미지 인시던트 LLM 분류 → 런타임 동적룰 자동 설치 ──
ANOMALY_PREFIXES = ("UNKNOWN", "ANOMALY")

def add_rule(base, token, rule):
    st, j = api(base, 'POST', '/api/v1/air/rules', token, {
        'ip':           rule.get('ip', '') or '',
        'method':       rule.get('method', '*') or '*',
        'pathContains': rule.get('pathContains', '') or '',
        'contains':     rule.get('contains', '') or '',
        'action':       rule.get('action', 'BLOCK') or 'BLOCK',
        'source':       'LLM',
    })
    return (j or {}).get('data', {}).get('id') if st == 200 else None

def set_shield(base, token, on):
    api(base, 'POST', f"/api/v1/air/defenses/air.shield/{'enable' if on else 'disable'}", token)

def handle_anomaly(inc, base, token):
    print(f"\n=== 이상 인시던트 LLM 분석: {inc['type']} (incident {inc['id']}) ===")
    verdict = llm_patcher.classify_and_rule(inc)
    if verdict is None:
        print("[*] LLM 미사용/실패 → 일반 shield 유지, 보류")
        return
    if not verdict.get('is_attack'):
        set_shield(base, token, False)                       # 오탐 → 광역 shield 완화
        set_status(base, token, inc['id'], 'PATCHED', 'LLM_FALSE_POSITIVE')
        print(f"[✓] 오탐 판정 → shield 완화. 사유: {verdict.get('reason')}")
        return
    rid = add_rule(base, token, verdict.get('rule') or {})    # 정밀 룰 자동 설치
    if verdict.get('relax_shield'):
        set_shield(base, token, False)                       # 정밀 룰로 대체 → 광역 shield 완화
    set_status(base, token, inc['id'], 'PATCHED', f"LLM_RULE:{rid}" if rid else "LLM_RULE_FAILED")
    print(f"[✓] 분류='{verdict.get('attack_class')}' sev={verdict.get('severity')} "
          f"→ 동적룰 설치({rid}) + shield {'완화' if verdict.get('relax_shield') else '유지'}")


# ── git ───────────────────────────────────────────────────────
def git(repo, *args, check=True):
    r = subprocess.run(['git', '-C', repo, *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} 실패: {r.stderr.strip()}")
    return r.stdout.strip()

def current_branch(repo):
    return git(repo, 'rev-parse', '--abbrev-ref', 'HEAD')


# ── 검증 (런타임 재공격) ──────────────────────────────────────
def verify(repo, scenario, admin_user, admin_pass):
    """verify.sh: 패치된 워킹트리로 throwaway 스택 빌드 → 가드 OFF로 재공격 → DEFENDED면 0."""
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'verify.sh')
    r = subprocess.run(['bash', script, repo, scenario, admin_user, admin_pass],
                       text=True)
    return r.returncode == 0


# ── 인시던트 1건 처리 ─────────────────────────────────────────
def handle(inc, base, token, repo, base_branch, do_verify, do_push, admin_user, admin_pass):
    itype = inc['type']
    vuln = VULNS[itype]
    branch = f"air/auto-patch/{inc['id'][:10].lower()}"
    print(f"\n=== 자동 패치 시작: {itype} (incident {inc['id']}) → {branch} ===")

    # 1) 깨끗한 base 에서 격리 브랜치 생성
    git(repo, 'checkout', base_branch)
    git(repo, 'checkout', '-B', branch, base_branch)

    # 2) 패치 생성/적용 (하이브리드)
    source = None
    for rel in vuln['files']:
        path = os.path.join(repo, rel)
        with open(path, encoding='utf-8') as f:
            original = f.read()

        patched = llm_patcher.generate_patch(rel, original, inc)   # LLM 시도
        if patched and vuln['validate'](rel, patched):
            source = 'LLM'
        else:
            if patched:
                print("[*] LLM 패치가 검증식 불통과 → 템플릿 폴백")
            patched = vuln['template'](rel, original)               # 템플릿 폴백
            if not patched or not vuln['validate'](rel, patched):
                print(f"[!] 패치 생성 실패: {rel} → 인시던트 FAILED")
                _rollback(repo, base_branch, branch)
                set_status(base, token, inc['id'], 'FAILED', 'PATCH_GEN_FAILED')
                return
            source = source or 'template'

        with open(path, 'w', encoding='utf-8') as f:
            f.write(patched)
        print(f"[*] 패치 적용({source}): {rel}")

    # 3) 검증: 런타임 플래그 OFF로 재공격 → 소스 자체로 막혀야 통과
    if do_verify:
        print("[*] 검증 시작(런타임 재공격, 가드 OFF)…")
        if not verify(repo, vuln['scenario'], admin_user, admin_pass):
            print("[!] 검증 실패(여전히 취약/빌드오류) → 롤백, 런타임 플래그 유지, FAILED")
            _rollback(repo, base_branch, branch)
            set_status(base, token, inc['id'], 'FAILED', 'VERIFY_FAILED')
            return
        print("[✓] 검증 통과: 소스 패치만으로 공격 차단됨")
    else:
        print("[*] --no-verify: 검증 생략")

    # 4) 커밋 (+push)
    git(repo, 'add', '-A')
    git(repo, 'commit', '-m',
        f"fix(air-auto): {itype} 자동 패치 [{source}] (incident {inc['id']})\n\n"
        f"AIR 오케스트레이터가 탐지된 공격에 대응해 자동 생성/검증한 소스 패치.\n"
        f"payload: {str(inc.get('payload'))[:120]}")
    action = f"AUTO_PATCHED:{source}:{branch}"
    if do_push:
        try:
            git(repo, 'push', '-u', 'origin', branch)
            action += ":pushed"
            print(f"[✓] push 완료: origin/{branch}")
        except RuntimeError as e:
            print(f"[!] push 실패(자격증명?): {e}")

    set_status(base, token, inc['id'], 'PATCHED', action)
    git(repo, 'checkout', base_branch)   # 다음 패치를 위해 base 복귀
    print(f"[✓] 완료: {itype} → status=PATCHED, branch={branch}")

def _rollback(repo, base_branch, branch):
    git(repo, 'checkout', '--', '.', check=False)
    git(repo, 'checkout', base_branch, check=False)
    git(repo, 'branch', '-D', branch, check=False)


# ── 메인 루프 ─────────────────────────────────────────────────
def run(args):
    repo_ok = bool(args.repo) and os.path.isdir(os.path.join(args.repo, '.git'))
    if args.repo and not repo_ok:
        print(f"[!] {args.repo} 는 git 저장소가 아님 → 소스패치 비활성(이상 LLM 분류만 동작)")
    base_branch = (args.branch_base or current_branch(args.repo)) if repo_ok else None
    print(f"[*] 오케스트레이터 시작: target={args.base} repo={args.repo or '(없음)'} base={base_branch} "
          f"verify={'on' if not args.no_verify else 'off'} push={'on' if args.push else 'off'}")

    token = login(args.base, args.admin_user, args.admin_pass)
    while True:
        st, j = api(args.base, 'GET', '/api/v1/air/incidents?limit=100', token)
        if st == 401:                       # 토큰 만료 재로그인
            token = login(args.base, args.admin_user, args.admin_pass); continue
        incidents = (j or {}).get('data', []) if st == 200 else []
        mitigated = [i for i in reversed(incidents) if i.get('status') == 'MITIGATED']  # 오래된 것부터
        known     = [i for i in mitigated if i.get('type') in VULNS]                    # 시그니처 → 소스패치
        anomalies = [i for i in mitigated if i.get('type') not in VULNS
                     and str(i.get('type', '')).startswith(ANOMALY_PREFIXES)]           # 미지/이상 → LLM 룰

        if known and repo_ok:
            print(f"[*] 소스패치 대상 {len(known)}건")
            for inc in known:
                try:
                    handle(inc, args.base, token, args.repo, base_branch,
                           not args.no_verify, args.push, args.admin_user, args.admin_pass)
                except Exception as e:
                    print(f"[!] 처리 중 예외: {e}")
                    _rollback(args.repo, base_branch, f"air/auto-patch/{inc['id'][:10].lower()}")
        elif known and not repo_ok:
            print(f"[.] 소스패치 대상 {len(known)}건 있으나 repo 없음 → 스킵(이상 LLM 분류만)")
        if anomalies:
            print(f"[*] 이상(LLM 분류) 대상 {len(anomalies)}건")
            for inc in anomalies:
                try:
                    handle_anomaly(inc, args.base, token)
                except Exception as e:
                    print(f"[!] 이상 처리 예외: {e}")
        if not known and not anomalies and not args.once:
            print(f"[.] 대기… ({args.interval}s)")
        if args.once:
            break
        time.sleep(args.interval)


def main():
    ap = argparse.ArgumentParser(description="AIR 자율 방어 오케스트레이터")
    ap.add_argument('--base', required=True, help='타깃 lab URL (예: http://localhost:8081)')
    ap.add_argument('--admin-user', required=True)
    ap.add_argument('--admin-pass', required=True)
    ap.add_argument('--repo', required=False, default=None,
                    help='패치 대상 git 저장소 경로(소스패치용). 없으면 이상 LLM 분류만 동작')
    ap.add_argument('--branch-base', default=None, help='패치 분기 기준 브랜치(기본: 현재 브랜치)')
    ap.add_argument('--interval', type=int, default=15, help='폴링 주기(초)')
    ap.add_argument('--once', action='store_true', help='1회만 처리 후 종료')
    ap.add_argument('--no-verify', action='store_true', help='런타임 재공격 검증 생략(빠른 데모)')
    ap.add_argument('--push', action='store_true', help='검증 통과 시 origin 으로 브랜치 push')
    run(ap.parse_args())

if __name__ == '__main__':
    main()
