"""렌더 — 통합 리포트(dict)를 Markdown 으로.

aggregate.py 에서 분리(SRP): 프레젠테이션만 책임진다(집계 로직과 독립 → 이후 render_html 등
출력 형식 추가가 correlate/sources 를 건드리지 않음). 입력은 build_report() 산출 dict.
"""
from __future__ import annotations


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
