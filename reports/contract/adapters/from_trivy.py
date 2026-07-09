"""trivy_for_llm.json → Finding[].

입력 스키마(scripts/extract_trivy.py 실측):
  {target, cve_id, severity, cvss_score, package_name, installed_version,
   fixed_version, title, description}
"""
from __future__ import annotations

from finding import Finding, Location, Source, Stage
from severity_map import normalize_severity


def to_findings(items: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for i, it in enumerate(items or []):
        cve = it.get("cve_id") or "UNKNOWN-CVE"
        pkg = it.get("package_name")
        out.append(
            Finding(
                id=f"trivy:{cve}:{pkg or ''}:{i}",
                source=Source.TRIVY,
                stage=Stage.BUILD,
                severity=normalize_severity("trivy", it.get("severity")),
                type=cve,
                title=it.get("title") or cve,
                location=Location(package=pkg, file=it.get("target")),
                message=(it.get("description") or "").strip() or None,
                evidence=(
                    f"{pkg} {it.get('installed_version', '?')} "
                    f"→ fix: {it.get('fixed_version', 'No Fix Available')}"
                ),
                # 의존성 취약점은 CWE 대신 CVE 로 상관 — correlation_key 는 type(CVE)로 자동 산출
                cwe=None,
                raw=it,
            )
        )
    return out
