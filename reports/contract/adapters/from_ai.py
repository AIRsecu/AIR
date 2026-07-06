"""AI 위험 재평가 판정 → Finding[]  (판정 캐리어).

현재 risk-eval-agent 는 판정을 ai_final_report.md(사람용 서술)로만 배출한다.
기계 병합을 위해 '구조화 판정 JSON'(ai_findings.json)을 추가로 배출해야 한다.
기대 입력 스키마(from_ai / emit_ai_findings 가 합의하는 계약):
  [{ scan_tool, rule_id?, cwe?, file_path?, line_number?,
     triage:{is_false_positive, reason},
     assessment:{final_risk, reason} }]

이 어댑터가 만든 Finding 은 correlation_key 로 스캐너 Finding 에 verdict 를 '보강'한다
(aggregate.enrich_with_ai 참고). 매칭 실패 시 독립 Finding 으로 남는다.
"""
from __future__ import annotations

from finding import Finding, Location, Severity, Source, Stage, Verdict, normalize_cwe
from severity_map import normalize_severity

_TOOL_STAGE = {"SAST": Stage.BUILD, "DAST": Stage.BUILD, "Trivy": Stage.BUILD}


def _final_risk(assessment: dict) -> Severity:
    return normalize_severity("ai", (assessment or {}).get("final_risk"))


def to_findings(items: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for i, it in enumerate(items or []):
        triage = it.get("triage") or {}
        assessment = it.get("assessment") or {}
        cwe = normalize_cwe(it.get("cwe"))
        sev = _final_risk(assessment)
        out.append(
            Finding(
                id=f"ai:{it.get('rule_id') or it.get('scan_tool', '?')}:{i}",
                source=Source.AI,
                stage=_TOOL_STAGE.get(it.get("scan_tool", ""), Stage.BUILD),
                severity=sev,
                type=it.get("rule_id") or it.get("scan_tool") or "ai-verdict",
                title="AI verdict",
                location=Location(file=it.get("file_path"), line=it.get("line_number")),
                cwe=cwe,
                verdict=Verdict(
                    is_false_positive=triage.get("is_false_positive"),
                    final_risk=sev,
                    # 판정 사유 키 이름 관용: Digrass 모델(model_dump)이 fp_reason/impact_reason
                    # 으로 뱉어도, 정규 reason 으로 뱉어도 모두 수용.
                    reason=(
                        assessment.get("reason")
                        or assessment.get("impact_reason")
                        or triage.get("reason")
                        or triage.get("fp_reason")
                    ),
                ),
                raw=it,
            )
        )
    return out
