"""정규 리포트 애그리게이터 — 팀 브랜치별 리포트를 하나로 통합한다.

흐름:
  1) reports/ 아래 각 소스 산출물을 발견(있는 것만)
  2) 소스별 어댑터로 정규 Finding 리스트로 변환
  3) AI 판정(verdict)을 correlation_key 로 스캐너 Finding 에 보강
  4) correlation_key 로 그룹핑 → 빌드↔런타임 교차 상관(핵심 스토리)
  5) unified_report.json + unified_report.md 배출

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
from datetime import datetime, timezone
from pathlib import Path

# 혼합 저장소(코드+산출물)에서 플랫 임포트가 되도록 이 디렉터리를 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from finding import Finding, Severity, Source, Stage  # noqa: E402
from adapters import from_ai, from_ir, from_semgrep, from_trivy, from_zap  # noqa: E402

_CONTRACT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _load_json(path: Path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _load_ir_records(reports_dir: Path) -> list[dict]:
    """IR 인시던트: 단일 JSON 배열 또는 incidents/*.json(레코드당 1파일) 둘 다 지원."""
    single = reports_dir / "ir" / "incidents.json"
    if single.exists():
        data = _load_json(single)
        return data if isinstance(data, list) else ([data] if data else [])
    inc_dir = reports_dir / "ir" / "incidents"
    if inc_dir.is_dir():
        out = []
        for p in sorted(inc_dir.glob("*.json")):
            rec = _load_json(p)
            if isinstance(rec, list):
                out.extend(rec)
            elif rec:
                out.append(rec)
        return out
    return []


def collect(reports_dir: Path) -> list[Finding]:
    """있는 소스만 골라 정규 Finding 으로 수집."""
    findings: list[Finding] = []

    semgrep = _load_json(reports_dir / "semgrep" / "semgrep_for_llm.json")
    if isinstance(semgrep, list):
        findings += from_semgrep.to_findings(semgrep)

    trivy = _load_json(reports_dir / "trivy" / "trivy_for_llm.json")
    if isinstance(trivy, list):
        findings += from_trivy.to_findings(trivy)

    zap = _load_json(reports_dir / "zap" / "zap_for_llm.json")
    if isinstance(zap, list):
        findings += from_zap.to_findings(zap)

    findings += from_ir.to_findings(_load_ir_records(reports_dir))
    return findings


def enrich_with_ai(findings: list[Finding], reports_dir: Path) -> list[Finding]:
    """ai_findings.json 이 있으면 verdict 를 스캐너 Finding 에 보강. 미매칭은 독립 추가."""
    ai_raw = _load_json(reports_dir / "summary" / "ai_findings.json")
    if not isinstance(ai_raw, list):
        return findings
    ai_findings = from_ai.to_findings(ai_raw)

    by_key: dict[str, list[Finding]] = {}
    for f in findings:
        if f.stage == Stage.BUILD:
            by_key.setdefault(f.correlation_key, []).append(f)

    unmatched: list[Finding] = []
    for af in ai_findings:
        targets = by_key.get(af.correlation_key)
        if targets:
            for t in targets:
                if t.verdict is None:
                    t.verdict = af.verdict
        else:
            unmatched.append(af)
    return findings + unmatched


def correlate(findings: list[Finding]) -> list[dict]:
    """correlation_key 로 그룹핑. 서로 다른 stage(빌드+런타임)가 함께 있으면 교차상관."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.correlation_key, []).append(f)

    result = []
    for key, items in groups.items():
        stages = {f.stage.value for f in items}
        sources = sorted({f.source.value for f in items})
        result.append(
            {
                "correlation_key": key,
                "sources": sources,
                "cross_stage": len(stages) > 1,   # ★ 빌드에서 발견 → 런타임에서 대응
                "top_severity": max((f.severity for f in items), key=lambda s: s.rank).value,
                "finding_ids": [f.id for f in items],
            }
        )
    # 교차상관 우선, 그다음 심각도순
    result.sort(key=lambda g: (not g["cross_stage"], -Severity(g["top_severity"]).rank))
    return result


def _sev_counts(findings: list[Finding]) -> dict[str, int]:
    c = {s.value: 0 for s in _SEV_ORDER}
    for f in findings:
        c[f.severity.value] += 1
    return c


def _source_counts(findings: list[Finding]) -> dict[str, int]:
    c: dict[str, int] = {}
    for f in findings:
        c[f.source.value] = c.get(f.source.value, 0) + 1
    return c


def build_report(findings: list[Finding]) -> dict:
    findings = sorted(findings, key=lambda f: (-f.severity.rank, f.source.value))
    correlations = correlate(findings)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "schema": "air.security.finding/v1",
        "totals": {
            "findings": len(findings),
            "by_severity": _sev_counts(findings),
            "by_source": _source_counts(findings),
            "cross_stage_correlations": sum(1 for c in correlations if c["cross_stage"]),
        },
        "correlations": correlations,
        "findings": [f.to_contract() for f in findings],
    }


def render_markdown(report: dict) -> str:
    t = report["totals"]
    lines = ["# 🛡 AIR 통합 보안 리포트 (Unified Security Report)", ""]
    lines.append(f"> 생성: {report['generated_at']}  ·  스키마 `{report['schema']}`")
    lines.append("")
    lines.append("## 요약")
    lines.append("")
    sev = t["by_severity"]
    lines.append("| CRITICAL | HIGH | MEDIUM | LOW | INFO | 합계 |")
    lines.append("|---:|---:|---:|---:|---:|---:|")
    lines.append(
        f"| {sev['CRITICAL']} | {sev['HIGH']} | {sev['MEDIUM']} | {sev['LOW']} "
        f"| {sev['INFO']} | {t['findings']} |"
    )
    lines.append("")
    lines.append(f"- 소스별: " + ", ".join(f"`{k}`={v}" for k, v in t["by_source"].items()))
    lines.append(f"- **빌드↔런타임 교차상관: {t['cross_stage_correlations']}건**")
    lines.append("")

    cross = [c for c in report["correlations"] if c["cross_stage"]]
    if cross:
        lines.append("## 🔗 빌드↔런타임 교차상관 (스캔에서 발견 → 런타임에서 대응)")
        lines.append("")
        lines.append("| 상관키 | 소스 | 최고 심각도 |")
        lines.append("|---|---|---|")
        for c in cross:
            lines.append(
                f"| `{c['correlation_key']}` | {', '.join(c['sources'])} | {c['top_severity']} |"
            )
        lines.append("")

    lines.append("## 전체 파인딩 (심각도순)")
    lines.append("")
    lines.append("| 심각도 | 소스 | 단계 | 유형 | 위치 | 판정/대응 |")
    lines.append("|---|---|---|---|---|---|")
    for f in report["findings"]:
        loc = f.get("location") or {}
        where = loc.get("file") or loc.get("endpoint") or loc.get("url") or loc.get("package") or "-"
        if loc.get("line"):
            where = f"{where}:{loc['line']}"
        extra = "-"
        if f.get("verdict"):
            v = f["verdict"]
            fp = "오탐" if v.get("is_false_positive") else "정탐"
            extra = f"AI:{fp}/{v.get('final_risk') or '-'}"
        elif f.get("response"):
            r = f["response"]
            extra = f"대응:{r.get('action_taken') or '-'}/{r.get('status') or '-'}"
        lines.append(
            f"| {f['severity']} | `{f['source']}` | {f['stage']} | {f['type']} | `{where}` | {extra} |"
        )
    lines.append("")
    return "\n".join(lines)


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
