"""semgrep_for_llm.json → Finding[].

입력 스키마(scripts/extract_semgrep.py 실측):
  {rule_id, severity, file_path, line_number, message, code_snippet, cwe}
"""
from __future__ import annotations

from typing import Any

from finding import Finding, Location, Source, Stage, normalize_cwe
from severity_map import normalize_severity


def _first_int(v: Any) -> int | None:
    if v is None:
        return None
    head = str(v).split("-")[0].strip()
    return int(head) if head.isdigit() else None


def to_findings(items: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for i, it in enumerate(items or []):
        rule = it.get("rule_id", "unknown-rule")
        out.append(
            Finding(
                id=f"semgrep:{rule}:{it.get('file_path', '')}:{it.get('line_number', '')}:{i}",
                source=Source.SEMGREP,
                stage=Stage.BUILD,
                severity=normalize_severity("semgrep", it.get("severity")),
                type=rule,
                title=rule,
                location=Location(file=it.get("file_path"), line=_first_int(it.get("line_number"))),
                message=(it.get("message") or "").strip() or None,
                evidence=(it.get("code_snippet") or "").strip() or None,
                cwe=normalize_cwe(it.get("cwe")),
                raw=it,
            )
        )
    return out
