"""Discord 알림 — **사후 대응 완료**를 알린다(앱의 1차 탐지 알림과 역할 분리).

  · 앱(Java DiscordNotifier)  = "🚨 공격 탐지 + 1차 가드 차단"
  · IR(이 모듈)               = "🛡 사후 대응 — IP 차단/연장/해제"
같은 인시던트라도 성격이 다른 두 알림이라 중복이 아니라 '타임라인'이 된다.
멱등 결과(EXTENDED)나 저위험(SKIPPED)은 소음이므로 신규 차단(BLOCKED)만 알린다.

Embed 리치화:
  - 등급별 color + 필드 구조화(유형/IP/모드/TTL/hits/endpoint/incidentId)
  - content 한 줄(타이틀) + embeds 동시 전송
  - HTTP/네트워크 실패 시 로그 + skip (텍스트 재전송 없음)

CRITICAL 채널 라우팅(선택):
  - DISCORD_WEBHOOK_URL_CRITICAL 이 있으면 CRITICAL 만 그쪽으로
  - 미설정이면 warning(프로세스당 1회) 후 기본 DISCORD_WEBHOOK_URL 로 fallback
  - 인프라 협조 없이도 기본 웹훅만으로 동작

앱과 동일한 하드닝: allowed_mentions parse:[] + 백틱 이스케이프(codeSafe).
웹훅 URL 은 env 로만 주입 — 코드/커밋에 넣지 않는다.
"""
from __future__ import annotations

import logging

import requests

from config.settings import Settings, get_settings, is_placeholder
from ir.analyzer.risk import RiskAssessment
from ir.models.incident import Incident, Severity
from ir.responder.ip_blocker import BlockAction, BlockResult

log = logging.getLogger("ir.notifier.discord")

_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}

# Embed color — notifier 전용(risk rules 와 관심사 분리)
_EMBED_COLOR: dict[str, int] = {
    "CRITICAL": 0xFF0000,
    "HIGH": 0xFF8C00,
    "MEDIUM": 0xFFD700,
    "LOW": 0x808080,
}


def _code_safe(s: str | None) -> str:
    """백틱 코드스팬에 넣을 공격자 영향 값 정리(앱 codeSafe 와 동일 규약)."""
    if not s or not s.strip():
        return "-"
    t = s.replace("`", "'").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return t[:300] + "…" if len(t) > 300 else t


def _build_content(incident: Incident, assessment: RiskAssessment, result: BlockResult) -> str:
    """Embed 와 함께 보낼 짧은 content(타이틀 한 줄). 클라이언트 호환용."""
    sev = assessment.severity.value
    emoji = _EMOJI.get(sev, "⚪")
    return (
        f"{emoji} **[AIR-IR] 사후 대응 완료 — IP 차단** "
        f"({sev}, risk {assessment.score})"
    )


def _build_embed(
    incident: Incident,
    assessment: RiskAssessment,
    result: BlockResult,
) -> dict:
    """Discord Embed dict. 필드 7개(+ title/description) — API 한도(25) 여유."""
    sev = assessment.severity.value
    return {
        "title": "[AIR-IR] 사후 대응 완료 — IP 차단",
        "description": f"{sev}, risk {assessment.score}",
        "color": _EMBED_COLOR.get(sev, 0x808080),
        "fields": [
            {"name": "유형", "value": f"`{_code_safe(incident.type)}`", "inline": True},
            {"name": "차단 IP", "value": f"`{_code_safe(result.ip)}`", "inline": True},
            {"name": "모드", "value": f"`{result.mode}`", "inline": True},
            {"name": "TTL", "value": f"`{result.ttl_seconds}s`", "inline": True},
            {"name": "누적", "value": f"`{result.hits}회`", "inline": True},
            {
                "name": "엔드포인트",
                "value": f"`{_code_safe(incident.endpoint)}`",
                "inline": False,
            },
            {
                "name": "인시던트",
                "value": f"`{_code_safe(incident.id)}`",
                "inline": False,
            },
        ],
    }


class DiscordNotifier:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        # CRITICAL 전용 웹훅 미설정 warning 은 프로세스당 1회만 (로그 폭탄 방지)
        self._warned_missing_critical: bool = False

    @property
    def enabled(self) -> bool:
        return self.settings.discord_enabled

    def _webhook_url_for(self, severity: Severity | str) -> str | None:
        """
        등급별 웹훅 URL.

        CRITICAL + critical URL 유효 → critical
        CRITICAL + critical 미설정 → warning(프로세스당 1회) 후 기본 URL fallback
        그 외 → 기본 URL
        """
        sev = severity.value if isinstance(severity, Severity) else str(severity)

        def _usable(url: str | None) -> bool:
            return bool(url) and not is_placeholder(url)

        default = self.settings.discord_webhook_url
        if sev == Severity.CRITICAL.value:
            crit = self.settings.discord_webhook_url_critical
            if _usable(crit):
                return crit
            if _usable(default):
                if not self._warned_missing_critical:
                    log.warning(
                        "[IR] DISCORD_WEBHOOK_URL_CRITICAL 미설정 — "
                        "CRITICAL 알림을 기본 웹훅으로 fallback"
                    )
                    self._warned_missing_critical = True
                return default
            return None

        return default if _usable(default) else None

    def notify_response(
        self,
        incident: Incident,
        assessment: RiskAssessment,
        result: BlockResult,
    ) -> bool:
        """신규 차단(BLOCKED)만 전송. 반환: 실제 전송 여부."""
        if not self.enabled:
            log.debug("[IR] Discord 미설정 — 알림 skip")
            return False
        if result.action is not BlockAction.BLOCKED:
            return False  # 연장/예외/저위험은 소음 → 알리지 않음

        url = self._webhook_url_for(assessment.severity)
        if not url:
            log.debug("[IR] Discord 웹훅 URL 없음 — 알림 skip")
            return False

        payload = {
            "content": _build_content(incident, assessment, result),
            "embeds": [_build_embed(incident, assessment, result)],
            "allowed_mentions": {"parse": []},
        }
        try:
            res = requests.post(url, json=payload, timeout=8)
            if res.status_code >= 300:
                log.warning(
                    "[IR] Discord 전송 실패: %s %s",
                    res.status_code,
                    res.text[:200],
                )
                return False
            log.info(
                "[IR] Discord 사후대응 알림 전송: %s (%s, %s)",
                result.ip,
                result.mode,
                assessment.severity.value,
            )
            return True
        except requests.RequestException as e:
            # Embed/텍스트 재전송 없음 — 소음·중복 방지
            log.warning("[IR] Discord 전송 예외: %s", e)
            return False
