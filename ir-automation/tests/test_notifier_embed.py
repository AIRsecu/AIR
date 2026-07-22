"""Discord Embed + CRITICAL 웹훅 라우팅(optional) 검증."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from config.settings import Settings
from ir.analyzer.risk import RiskAssessment
from ir.models.incident import Incident, Severity
from ir.notifier.discord import (
    DiscordNotifier,
    _EMBED_COLOR,
    _build_content,
    _build_embed,
    _code_safe,
)
from ir.responder.ip_blocker import BlockAction, BlockResult


def _settings(**kwargs) -> Settings:
    base = dict(
        discord_webhook_url="https://discord.com/api/webhooks/default-hook",
        discord_webhook_url_critical=None,
        block_mode="simulation",
        incident_storage_path=__import__("pathlib").Path("/tmp/ir-test-inc"),
        blocklist_path=__import__("pathlib").Path("/tmp/ir-test-bl.json"),
        default_block_duration=60,
        critical_block_duration=120,
        allowlist_ips=[],
        block_private_ips=False,
    )
    base.update(kwargs)
    return Settings(**base)


def _incident(**kwargs) -> Incident:
    data = {
        "id": "01HXEMBED",
        "type": "XSS_ATTEMPT",
        "endpoint": "/api/v1/products/search",
        "clientIp": "203.0.113.50",
    }
    data.update(kwargs)
    return Incident.model_validate(data)


def _assessment(
    sev: Severity = Severity.HIGH,
    score: int = 75,
    *,
    base_sev: Severity | None = None,
    base_score: int | None = None,
) -> RiskAssessment:
    base_sev = base_sev or sev
    base_score = base_score if base_score is not None else score
    return RiskAssessment(
        base_score=base_score,
        base_severity=base_sev,
        score=score,
        severity=sev,
        block_seconds=60,
    )


def _blocked(ip: str = "203.0.113.50") -> BlockResult:
    return BlockResult(
        action=BlockAction.BLOCKED,
        ip=ip,
        mode="simulation",
        ttl_seconds=60,
        hits=1,
    )


# ── Embed 빌더 ───────────────────────────────────────────────

def test_build_embed_fields_and_color():
    inc = _incident()
    emb = _build_embed(inc, _assessment(Severity.HIGH, 75), _blocked())
    assert emb["color"] == _EMBED_COLOR["HIGH"]
    assert emb["description"] == "HIGH, risk 75"
    names = [f["name"] for f in emb["fields"]]
    assert names == ["유형", "차단 IP", "모드", "TTL", "누적", "엔드포인트", "인시던트"]
    assert "`XSS_ATTEMPT`" in emb["fields"][0]["value"]
    assert "`01HXEMBED`" in emb["fields"][-1]["value"]


def test_build_embed_divergence_label():
    """base HIGH → effective CRITICAL (+context) 표기."""
    hybrid = _assessment(
        Severity.CRITICAL, 90,
        base_sev=Severity.HIGH, base_score=75,
    )
    emb = _build_embed(_incident(), hybrid, _blocked())
    assert emb["description"] == "HIGH → CRITICAL (+context), risk 90"
    assert emb["color"] == _EMBED_COLOR["CRITICAL"]  # embed color = effective


def test_code_safe_strips_backticks():
    assert "`" not in _code_safe("a`b")
    assert _code_safe(None) == "-"
    assert _code_safe("   ") == "-"


def test_build_content_one_liner():
    c = _build_content(_incident(), _assessment(), _blocked())
    assert "[AIR-IR]" in c and "HIGH" in c and "75" in c


# ── 라우팅 ───────────────────────────────────────────────────

def test_webhook_critical_uses_dedicated_url():
    n = DiscordNotifier(_settings(
        discord_webhook_url_critical="https://discord.com/api/webhooks/crit-hook",
    ))
    crit = _assessment(Severity.CRITICAL, 95)
    high = _assessment(Severity.HIGH, 75)
    assert n._webhook_url_for(crit).endswith("crit-hook")
    assert n._webhook_url_for(high).endswith("default-hook")


def test_webhook_effective_critical_base_high_uses_default():
    """XSS base HIGH + context → effective CRITICAL 이어도 CRITICAL 웹훅 안 탐."""
    n = DiscordNotifier(_settings(
        discord_webhook_url_critical="https://discord.com/api/webhooks/crit-hook",
    ))
    hybrid = _assessment(
        Severity.CRITICAL, 90,
        base_sev=Severity.HIGH, base_score=75,
    )
    assert n._webhook_url_for(hybrid).endswith("default-hook")


def test_webhook_critical_fallback_warns(caplog):
    n = DiscordNotifier(_settings(discord_webhook_url_critical=None))
    crit = _assessment(Severity.CRITICAL, 95)
    with caplog.at_level("WARNING", logger="ir.notifier.discord"):
        url = n._webhook_url_for(crit)
    assert url.endswith("default-hook")
    assert "DISCORD_WEBHOOK_URL_CRITICAL" in caplog.text
    assert n._warned_missing_critical is True


def test_webhook_critical_fallback_warns_only_once(caplog):
    n = DiscordNotifier(_settings(discord_webhook_url_critical=None))
    crit = _assessment(Severity.CRITICAL, 95)
    with caplog.at_level("WARNING", logger="ir.notifier.discord"):
        n._webhook_url_for(crit)
        first = len(caplog.records)
        n._webhook_url_for(crit)
        second = len(caplog.records)
    assert first >= 1
    assert second == first  # 두 번째 호출에서 WARNING 추가 없음
    assert n._warned_missing_critical is True


def test_webhook_critical_placeholder_treated_as_unset(caplog):
    n = DiscordNotifier(_settings(
        discord_webhook_url_critical="https://discord.com/api/webhooks/[critical-webhook-url-here]",
    ))
    crit = _assessment(Severity.CRITICAL, 95)
    with caplog.at_level("WARNING", logger="ir.notifier.discord"):
        url = n._webhook_url_for(crit)
    assert url.endswith("default-hook")


# ── notify_response ──────────────────────────────────────────

def test_notify_sends_embed_payload():
    n = DiscordNotifier(_settings())
    mock_res = MagicMock(status_code=204, text="")
    with patch("ir.notifier.discord.requests.post", return_value=mock_res) as post:
        ok = n.notify_response(_incident(), _assessment(), _blocked())
    assert ok is True
    args, kwargs = post.call_args
    assert args[0].endswith("default-hook")
    body = kwargs["json"]
    assert "embeds" in body and len(body["embeds"]) == 1
    assert body["allowed_mentions"] == {"parse": []}
    assert "[AIR-IR]" in body["content"]


def test_notify_critical_routes_to_critical_webhook():
    n = DiscordNotifier(_settings(
        discord_webhook_url_critical="https://discord.com/api/webhooks/crit-hook",
    ))
    mock_res = MagicMock(status_code=204, text="")
    with patch("ir.notifier.discord.requests.post", return_value=mock_res) as post:
        n.notify_response(
            _incident(type="SQLI_ATTEMPT"),
            _assessment(Severity.CRITICAL, 95),
            _blocked(),
        )
    assert post.call_args.args[0].endswith("crit-hook")


def test_notify_skips_extended():
    n = DiscordNotifier(_settings())
    with patch("ir.notifier.discord.requests.post") as post:
        ok = n.notify_response(
            _incident(),
            _assessment(),
            BlockResult(BlockAction.EXTENDED, "203.0.113.50", "simulation", 60, 2),
        )
    assert ok is False
    post.assert_not_called()


def test_notify_disabled_when_no_webhook(settings):
    # conftest settings: discord_webhook_url=None
    n = DiscordNotifier(settings)
    assert n.enabled is False
    with patch("ir.notifier.discord.requests.post") as post:
        assert n.notify_response(_incident(), _assessment(), _blocked()) is False
    post.assert_not_called()


def test_notify_http_failure_no_retry():
    n = DiscordNotifier(_settings())
    mock_res = MagicMock(status_code=400, text="bad embed")
    with patch("ir.notifier.discord.requests.post", return_value=mock_res) as post:
        ok = n.notify_response(_incident(), _assessment(), _blocked())
    assert ok is False
    assert post.call_count == 1  # 텍스트 재전송 없음
