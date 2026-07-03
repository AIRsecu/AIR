"""위험도 분석 — 앱 `com.shop.air.RiskScoring` 을 그대로 포팅.

점수/등급 표를 앱과 **동일한 값**으로 유지해야 앱 알림과 IR 알림이 어긋나지 않는다.
(앱이 score 를 넘겨주면 그대로 신뢰하고, 없으면 유형 기반으로 재산정한다.)
"""
from __future__ import annotations

from dataclasses import dataclass

from config.settings import Settings, get_settings
from ir.models.incident import Incident, Severity

# 앱 RiskScoring.SCORE 와 1:1 동일. 값이 바뀌면 양쪽을 함께 고쳐야 한다.
_SCORE: dict[str, int] = {
    "SQLI_ATTEMPT": 95,
    "RANSOM_MASSDELETE": 95,
    "UPLOAD_MALICIOUS_FILE": 90,
    "ORDER_NEGATIVE_QTY": 85,
    "UPLOAD_PATH_TRAVERSAL": 85,
    "IDOR_ATTEMPT": 80,
    "XSS_ATTEMPT": 75,
    "DDOS_FLOOD": 70,
    "ANOMALY_5XX_BURST": 60,
    "ANOMALY_SCAN": 50,
}
_UNKNOWN_SCORE = 30  # 앱과 동일: 미지 유형 LOW(30)


def score(attack_type: str) -> int:
    return _SCORE.get(attack_type, _UNKNOWN_SCORE)


def severity(attack_type: str) -> Severity:
    s = score(attack_type)
    if s >= 90:
        return Severity.CRITICAL
    if s >= 70:
        return Severity.HIGH
    if s >= 40:
        return Severity.MEDIUM
    return Severity.LOW


@dataclass(frozen=True)
class RiskAssessment:
    """analyzer 산출물 — responder/notifier 가 소비."""

    score: int
    severity: Severity
    block_seconds: int  # 이 등급에 적용할 차단 TTL(초)

    @property
    def should_block(self) -> bool:
        # MEDIUM 이상만 네트워크 차단(LOW 는 기록/알림만) — 오차단 최소화
        return self.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)


def assess(incident: Incident, settings: Settings | None = None) -> RiskAssessment:
    settings = settings or get_settings()
    sev = severity(incident.type)
    return RiskAssessment(
        score=score(incident.type),
        severity=sev,
        block_seconds=settings.duration_for(sev.value),
    )
