#!/usr/bin/env python3
"""
공격 스크립트 순차 실행 → reports/dast/dast-results.json 생성

사용:
  poetry run python dast/run_all.py --base <URL> --admin-user <u> --admin-pass <pw>

종료코드: 취약점 발견=1, 전체 방어=0
"""
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

_ATTACKS_DIR = Path(__file__).parent / "attacks"
_OUT_FILE = Path(__file__).parent.parent / "reports" / "dast" / "dast-results.json"

# 새 스크립트 추가 시 이 목록에 항목 1개만 추가한다.
SCRIPTS: list[dict] = [
    {
        "script": "sqli_attack.py",
        "auth": True,
        "attack_type": "SQLI_ATTEMPT",
        "severity": "CRITICAL",
        "cwe": "89",
        "endpoint": "/api/v1/tenants/{tid}/products/search",
        "evidence": "' OR '1'='1",
        "message": "SQL Injection — OR 1=1 페이로드로 전체 상품 반환",
    },
    {
        "script": "xss_attack.py",
        "auth": True,
        "attack_type": "XSS_ATTEMPT",
        "severity": "HIGH",
        "cwe": "79",
        "endpoint": "/api/v1/tenants/{tid}/products",
        "evidence": "<script>alert(1)</script>",
        "message": "Stored XSS — 상품명 스크립트 페이로드 저장 후 원문 반환",
    },
    {
        "script": "neg_qty_attack.py",
        "auth": True,
        "attack_type": "ORDER_NEGATIVE_QTY",
        "severity": "HIGH",
        "cwe": "840",
        "endpoint": "/api/v1/tenants/{tid}/orders",
        "evidence": "quantity=-100",
        "message": "음수 수량 주문 — 잔액 오히려 증가하는 Business Logic 취약점",
    },
    {
        "script": "idor_attack.py",
        "auth": True,
        "attack_type": "IDOR_ATTEMPT",
        "severity": "HIGH",
        "cwe": "639",
        "endpoint": "/api/v1/tenants/{tid}/orders/{oid}",
        "evidence": "공격자 토큰으로 피해자 주문 직접 조회",
        "message": "IDOR — 소유자 검증 없이 타인 주문 데이터 반환",
    },
    {
        "script": "ddos_attack.py",
        "auth": False,
        "attack_type": "DDOS_FLOOD",
        "severity": "HIGH",
        "cwe": None,
        "endpoint": "/api/v1/health",
        "evidence": "60회 연속 요청 (RATE_LIMIT=30/10s 초과)",
        "message": "DDoS Rate Flood — 10초 창 내 한도 초과로 429 유도",
        "sleep_after": 12,
    },
    {
        "script": "ransom_attack.py",
        "auth": True,
        "attack_type": "RANSOM_MASSDELETE",
        "severity": "CRITICAL",
        "cwe": None,
        "endpoint": "/api/v1/tenants/{tid}/products/{pid}",
        "evidence": "상품 10개 연속 DELETE (MASSDELETE_LIMIT=5 초과)",
        "message": "대량 삭제(랜섬 유사) — 연속 삭제로 massdelete-guard 트리거",
        "sleep_after": 12,
    },
    {
        "script": "upload_attack.py",
        "auth": True,
        "attack_type": "UPLOAD_MALICIOUS_FILE",
        "severity": "CRITICAL",
        "cwe": "434",
        "endpoint": "/api/v1/tenants/{tid}/uploads",
        "evidence": "shell.jsp (위험 확장자), ../evil.png (경로조작), ../../etc/passwd (LFI)",
        "message": "파일 업로드 3종 벡터 — 위험 확장자·경로조작·LFI",
        "sleep_after": 12,
    },
    {
        "script": "rowcap_attack.py",
        "auth": True,
        "attack_type": None,
        "severity": "MEDIUM",
        "cwe": None,
        "endpoint": "/api/v1/tenants/{tid}/products",
        "evidence": "상품 250개 생성 후 일괄 GET (ROW_CAP=200 초과)",
        "message": "대량 데이터 수집 — 단일 응답 규모 제한(row-cap) 우회 시도",
    },
    {
        "script": "anomaly_attack.py",
        "auth": False,
        "attack_type": "ANOMALY_SCAN",
        "severity": "MEDIUM",
        "cwe": None,
        "endpoint": "/api/v1/no-such-endpoint",
        "evidence": "비존재 경로 25회 반복 요청 (BURST_4XX=20 초과)",
        "message": "이상탐지 — 4xx 스캔으로 anomaly.detection → air.shield 자동 활성화",
    },
]


class DastFinding(BaseModel):
    attack_type: str | None
    result: str
    severity: str
    cwe: str | None
    endpoint: str
    url: str
    evidence: str
    message: str
    script: str


class DastReport(BaseModel):
    generated_at: str
    findings: list[DastFinding]


def _run(config: dict, base: str, admin_user: str, admin_pass: str) -> int:
    cmd = [sys.executable, str(_ATTACKS_DIR / config["script"]), "--base", base]
    if config["auth"]:
        cmd += ["--admin-user", admin_user, "--admin-pass", admin_pass]
    return subprocess.run(cmd).returncode


def _finding(config: dict, base: str) -> DastFinding:
    return DastFinding(
        attack_type=config["attack_type"],
        result="VULNERABLE",
        severity=config["severity"],
        cwe=config["cwe"],
        endpoint=config["endpoint"],
        url=base.rstrip("/") + config["endpoint"],
        evidence=config["evidence"],
        message=config["message"],
        script=config["script"],
    )


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:8081")
    p.add_argument("--admin-user", required=True)
    p.add_argument("--admin-pass", required=True)
    args = p.parse_args()

    findings: list[DastFinding] = []
    for cfg in SCRIPTS:
        print(f"\n{'=' * 60}")
        print(f"[*] 실행: {cfg['script']}")
        print(f"{'=' * 60}")
        code = _run(cfg, args.base, args.admin_user, args.admin_pass)
        if code == 1:  # VULNERABLE — exit code 컨벤션: 취약=1, 방어=0
            findings.append(_finding(cfg, args.base))
            print(f"[!] {cfg['script']}: VULNERABLE")
        else:
            print(f"[+] {cfg['script']}: DEFENDED")
        if sleep := cfg.get("sleep_after", 0):
            print(f"[~] {sleep}초 대기 중 (슬라이딩 윈도우 만료)...")
            time.sleep(sleep)

    report = DastReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings=findings,
    )

    _OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _OUT_FILE.write_text(
        json.dumps(report.model_dump(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    total = len(SCRIPTS)
    vuln = len(findings)
    print(f"\n{'=' * 60}")
    print(f"[+] 결과: {vuln}개 취약점 발견 / {total - vuln}개 방어됨")
    print(f"[+] 저장: {_OUT_FILE}")
    print(f"{'=' * 60}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
