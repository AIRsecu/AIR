"""정규 리포트 애그리게이터 — CLI 진입 + 파이프라인 배선(loader→correlate→render→writer).

책임 분리(SRP):
  - 소스 발견·로딩 = sources.py
  - 상관·집계      = correlate.py
  - 렌더           = render.py
  - 이 파일        = CLI + 배선 + 후방호환 재노출
    (기존 `import aggregate; aggregate.collect(...)` / 테스트 / `python aggregate.py` 진입점 유지)

사용:
  python reports/contract/aggregate.py                 # reports/ 실산출물 통합
  python reports/contract/aggregate.py --demo          # 번들 샘플로 즉시 시연
  python reports/contract/aggregate.py --reports-dir X --out-dir Y
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# 혼합 저장소(코드+산출물)에서 플랫 임포트가 되도록 이 디렉터리를 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sources  # noqa: E402
import correlate as _corr  # noqa: E402
import render as _render  # noqa: E402

# ── 후방호환 재노출: 기존 임포트 경로/테스트/CI 가 aggregate.<name> 를 계속 쓰도록 유지 ──
collect = sources.collect
enrich_with_ai = _corr.enrich_with_ai
correlate = _corr.correlate
build_report = _corr.build_report
render_markdown = _render.render_markdown
_load_json = sources._load_json

_CONTRACT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="AIR 정규 리포트 애그리게이터")
    ap.add_argument("--reports-dir", default="reports", help="스캔 산출물 루트 (기본 reports/)")
    ap.add_argument("--out-dir", default=None, help="출력 디렉터리 (기본 <reports-dir>/summary)")
    ap.add_argument("--demo", action="store_true", help="번들 샘플로 시연")
    args = ap.parse_args(argv)

    try:  # Windows 콘솔에서도 한글 출력이 깨지지 않도록
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    reports_dir = _CONTRACT_DIR / "samples" if args.demo else Path(args.reports_dir)
    out_dir = Path(args.out_dir) if args.out_dir else (reports_dir / "summary")
    out_dir.mkdir(parents=True, exist_ok=True)

    findings = collect(reports_dir)
    findings = enrich_with_ai(findings, reports_dir)
    report = build_report(findings)

    (out_dir / "unified_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out_dir / "unified_report.md").write_text(render_markdown(report), encoding="utf-8")

    t = report["totals"]
    print(
        f"[+] 통합 완료: findings={t['findings']} "
        f"(CRIT {t['by_severity']['CRITICAL']} / HIGH {t['by_severity']['HIGH']}), "
        f"교차상관={t['cross_stage_correlations']}"
    )
    print(f"    → {out_dir / 'unified_report.json'}")
    print(f"    → {out_dir / 'unified_report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
