"""심각도 어휘 매핑 — 3종 어휘를 정규 taxonomy 1종으로.

발산 현황(브랜치별 실측):
  - semgrep_for_llm : ERROR / WARNING / INFO        (semgrep severity)
  - trivy_for_llm   : CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
  - zap_for_llm     : riskdesc 예) "High (Medium)"  (첫 토큰만 사용)
  - AI final_risk   : Critical / High / Medium / Low / Info
  - IR risk.severity: CRITICAL / HIGH / MEDIUM / LOW (Info 없음)
"""
from __future__ import annotations

import re
from typing import Optional

from finding import Severity

_SEMGREP = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.INFO}
_TRIVY = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW, "UNKNOWN": Severity.INFO,
}
_ZAP = {
    "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
    "INFORMATIONAL": Severity.INFO, "INFO": Severity.INFO,
}
_TITLECASE = {  # AI / IR 공통 — 이미 정규 어휘에 가깝다
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW, "INFO": Severity.INFO, "INFORMATIONAL": Severity.INFO,
}

_TABLES = {
    "semgrep": _SEMGREP,
    "trivy": _TRIVY,
    "zap": _ZAP,
    "ai": _TITLECASE,
    "ir-runtime": _TITLECASE,
    "app": _TITLECASE,
}


def normalize_severity(source: str, raw: Optional[str]) -> Severity:
    """소스별 원본 심각도 문자열 → 정규 Severity. 미상은 INFO 로 보수적 처리."""
    if raw is None:
        return Severity.INFO
    token = str(raw).strip()
    if source == "zap":
        # "High (Medium)" → "High" 처럼 첫 알파 토큰만
        m = re.match(r"\s*([A-Za-z]+)", token)
        token = m.group(1) if m else token
    key = token.upper()
    table = _TABLES.get(source, _TITLECASE)
    return table.get(key, Severity.INFO)
