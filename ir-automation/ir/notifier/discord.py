"""Discord 알림 — **사후 대응 완료**를 알린다(앱의 1차 탐지 알림과 역할 분리).

  · 앱(Java DiscordNotifier)  = "🚨 공격 탐지 + 1차 가드 차단"
  · IR(이 모듈)               = "🛡 사후 대응 — IP 차단/연장/해제"
같은 인시던트라도 성격이 다른 두 알림이라 중복이 아니라 '타임라인'이 된다.
멱등 결과(EXTENDED)나 저위험(SKIPPED)은 소음이므로 신규 차단(BLOCKED)만 알린다.

앱과 동일한 하드닝을 적용: allowed_mentions parse:[] + 백틱 이스케이프(codeSafe).
웹훅 URL 은 env(DISCORD_WEBHOOK_URL)로만 주입 — 코드/커밋에 넣지 않는다.
"""
from __future__ import annotations

import logging

import requests

from config.settings import Settings, get_settings
from ir.analyzer.risk import RiskAssessment
from ir.models.incident import Incident
from ir.responder.ip_blocker import BlockAction, BlockResult

log = logging.getLogger("ir.notifier.discord")

_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}


def _code_safe(s: str | None) -> str:
    """백틱 코드스팬에 넣을 공격자 영향 값 정리(앱 codeSafe 와 동일 규약)."""
    if not s or not s.strip():
        return "-"
    t = s.replace("`", "'").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return t[:300] + "…" if len(t) > 300 else t


class DiscordNotifier:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    @property
    def enabled(self) -> bool:
        return self.settings.discord_enabled

    def notify_response(self, incident: Incident, assessment: RiskAssessment,
                        result: BlockResult) -> bool:
        """신규 차단(BLOCKED)만 전송. 반환: 실제 전송 여부."""
        if not self.enabled:
            log.debug("[IR] Discord 미설정 — 알림 skip")
            return False
        if result.action is not BlockAction.BLOCKED:
            return False  # 연장/예외/저위험은 소음 → 알리지 않음

        sev = assessment.severity.value
        emoji = _EMOJI.get(sev, "⚪")
        content = (
            f"{emoji} **[AIR-IR] 사후 대응 완료 — IP 차단** ({sev}, risk {assessment.score})\n"
            f"• 유형: `{_code_safe(incident.type)}`\n"
            f"• 차단 IP: `{_code_safe(result.ip)}`\n"
            f"• 모드: `{result.mode}`  · TTL: `{result.ttl_seconds}s`  · 누적: `{result.hits}회`\n"
            f"• 엔드포인트: `{_code_safe(incident.endpoint)}`\n"
            f"• 인시던트: `{_code_safe(incident.id)}`"
        )
        payload = {"content": content, "allowed_mentions": {"parse": []}}
        try:
            res = requests.post(self.settings.discord_webhook_url, json=payload, timeout=8)
            if res.status_code >= 300:
                log.warning("[IR] Discord 전송 실패: %s %s", res.status_code, res.text[:200])
                return False
            log.info("[IR] Discord 사후대응 알림 전송: %s (%s)", result.ip, result.mode)
            return True
        except requests.RequestException as e:
            log.warning("[IR] Discord 전송 예외: %s", e)
            return False
