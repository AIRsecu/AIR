"""zap_for_llm.json → Finding[].

입력 스키마(scripts/extract_zap.py 실측):
  {alert_name, risk_level, cwe_id, description, solution, instances_count,
   affected_targets:[{url, method, parameter, evidence}]}
"""
from __future__ import annotations

from finding import Finding, Location, Source, Stage, normalize_cwe
from severity_map import normalize_severity


def to_findings(items: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for i, it in enumerate(items or []):
        name = it.get("alert_name") or "unknown-alert"
        targets = it.get("affected_targets") or []
        first = targets[0] if targets else {}
        out.append(
            Finding(
                id=f"zap:{name}:{i}",
                source=Source.ZAP,
                stage=Stage.BUILD,
                severity=normalize_severity("zap", it.get("risk_level")),
                type=name,
                title=name,
                location=Location(
                    url=first.get("url"),
                    endpoint=first.get("url"),
                ),
                message=(it.get("description") or "").strip() or None,
                evidence=first.get("evidence") or None,
                cwe=normalize_cwe(it.get("cwe_id")),
                raw=it,
            )
        )
    return out
