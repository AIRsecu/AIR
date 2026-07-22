#!/usr/bin/env python3
"""
파일 업로드 공격 스크립트 (웹셸/경로조작/LFI)

대상: POST /api/v1/tenants/{tenantId}/uploads (multipart)
     GET  /api/v1/tenants/{tenantId}/uploads/download?name=...
upload.file-guard 및 air.detection 활성 여부로 VULNERABLE/DEFENDED 를 판정한다.

autoDetect 가 요청 내에서 탐지 즉시 upload.file-guard 를 ON 으로 전환하므로
air.detection=ON 만으로 같은 요청부터 방어가 시작된다.

벡터:
  1. 위험 확장자 업로드 — shell.jsp → storedName 에 .jsp 유지 시 취약
  2. 경로조작 업로드 — ../evil.png → storedName 에 경로 포함 시 취약
  3. LFI (경로조작 읽기) — download?name=../../etc/passwd → HTTP 200 시 취약

사용:
  python upload_attack.py --base http://localhost:8081 --admin-user <super_admin> --admin-pass <pw>

종료코드: 공격 성공(취약)=1, 방어됨=0
"""
import argparse
import random
import sys
import time

import requests

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")


def call(method, url, token=None, body=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = requests.request(method, url, json=body, headers=headers, timeout=15)
        try:
            j = r.json()
        except Exception:
            j = None
        return r.status_code, j
    except requests.RequestException as e:
        raise SystemExit(f"[!] 요청 실패({method} ...{url[-40:]}): {e}")


def login(base, username, password):
    url = base.rstrip("/") + "/api/v1/auth/login"
    st, j = call("POST", url, body={"username": username, "password": password})
    if st != 200 or not j or not j.get("data"):
        raise SystemExit(f"[!] 로그인 실패({username}): {st} {j}")
    return j["data"]["accessToken"]


def prepare(base, token):
    suffix = f"{int(time.time())}{random.randint(100, 999)}"
    url = base.rstrip("/") + "/api/v1/tenants"
    st, j = call("POST", url, token,
                 {"name": f"dast-upload-{suffix}", "slug": f"dast-upload-{suffix}"})
    if st not in (200, 201) or not j or not j.get("data"):
        raise SystemExit(f"[!] 테넌트 생성 실패: {st} {j}")
    return j["data"]["id"]


def upload(base, tid, token, filename, content):
    url = f"{base.rstrip('/')}/api/v1/tenants/{tid}/uploads"
    headers = {"Authorization": f"Bearer {token}"}
    files = {"file": (filename, content, "application/octet-stream")}
    try:
        r = requests.post(url, files=files, headers=headers, timeout=15)
        try:
            j = r.json()
        except Exception:
            j = None
        return r.status_code, j
    except requests.RequestException as e:
        raise SystemExit(f"[!] 업로드 실패({filename}): {e}")


def download_status(base, tid, token, name):
    url = f"{base.rstrip('/')}/api/v1/tenants/{tid}/uploads/download"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(url, params={"name": name}, headers=headers, timeout=15)
        return r.status_code
    except requests.RequestException as e:
        raise SystemExit(f"[!] 다운로드 실패: {e}")


def run(base, admin_user, admin_pass):
    token = login(base, admin_user, admin_pass)
    tid = prepare(base, token)
    print(f"[*] 준비 완료: tenant={tid}")

    vuln = {}

    print("[>] 벡터1: 위험 확장자 업로드 (shell.jsp)")
    st, j = upload(base, tid, token, "shell.jsp",
                   b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>")
    stored = ((j or {}).get("data") or {}).get("storedName", "")
    v1 = st == 201 and stored.endswith(".jsp")
    print(f"[<] HTTP {st}, storedName={stored!r} → {'VULNERABLE' if v1 else 'DEFENDED'}")
    vuln["위험 확장자"] = v1

    print("[>] 벡터2: 경로조작 업로드 (../evil.png)")
    st, j = upload(base, tid, token, "../evil.png", b"\x89PNG\r\n\x1a\n")
    stored = ((j or {}).get("data") or {}).get("storedName", "")
    v2 = st == 201 and (".." in stored or "/" in stored)
    print(f"[<] HTTP {st}, storedName={stored!r} → {'VULNERABLE' if v2 else 'DEFENDED'}")
    vuln["경로조작 업로드"] = v2

    print("[>] 벡터3: LFI 읽기 (download?name=../../etc/passwd)")
    st = download_status(base, tid, token, "../../etc/passwd")
    v3 = st == 200
    print(f"[<] HTTP {st} → {'VULNERABLE' if v3 else 'DEFENDED'}")
    vuln["LFI"] = v3

    hit = [k for k, v in vuln.items() if v]
    if hit:
        print(f"\n[RESULT] VULNERABLE — {len(hit)}/3 벡터 성공: {hit}")
        return 1
    print("\n[RESULT] DEFENDED — 전체 벡터 차단 (upload.file-guard + autoDetect 적용)")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:8081")
    p.add_argument("--admin-user", required=True)
    p.add_argument("--admin-pass", required=True)
    args = p.parse_args()
    raise SystemExit(run(args.base, args.admin_user, args.admin_pass))
