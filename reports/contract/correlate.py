"""상관·집계 — 수집된 Finding 을 AI 판정으로 보강하고 correlation_key 로 교차상관, 통계 산출.

aggregate.py 에서 분리(SRP): '수집된 것을 어떻게 엮고 요약하는가'(순수 로직)만 책임진다.
파일 I/O 는 sources.py(_load_json 재사용), 렌더는 render.py.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# 혼합 저장소(코드+산출물)에서 플랫 임포트가 되도록 이 디렉터리를 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from finding import Finding, Severity, Stage  # noqa: E402
from adapters import from_ai  # noqa: E402
from sources import _load_json  # noqa: E402

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


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
