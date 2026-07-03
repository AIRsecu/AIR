"""ir-automation 설정 — .env 에서 로드(로컬 전용, 커밋 금지).

민감정보(Discord 웹훅 URL / AWS 자격증명)는 코드에 넣지 않고 env 로만 주입한다.
차단 관련 안전장치(allowlist·사설IP 보호·기본 simulation)를 여기에 모아 둔다.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Discord .env.example 의 플레이스홀더([webhook-url-here]) 는 '미설정'으로 취급
_PLACEHOLDER_MARK = "["


def _csv(name: str, default: str = "") -> list[str]:
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


# 유효한 차단 모드. 기본 simulation — 실수로 실 IP 를 막지 않는다.
BLOCK_MODES = ("simulation", "nginx", "aws_waf")

# '개발망' 보호 대역 — 명시적으로 정의(RFC1918 + loopback + link-local).
# ※ ipaddress.is_private 는 Python 3.12+ 에서 문서/예약 대역까지 포함하도록 바뀌어
#    실제 공인 공격 IP 판정에 부적합 → 아래 대역만 정확히 보호한다.
_PROTECTED_NETS = tuple(
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC1918
        "127.0.0.0/8", "::1/128",                          # loopback
        "169.254.0.0/16", "fe80::/10",                     # link-local
        "fc00::/7",                                        # IPv6 ULA
    )
)


def _is_protected(addr: ipaddress._BaseAddress) -> bool:
    return any(addr in net for net in _PROTECTED_NETS)


@dataclass(frozen=True)
class Settings:
    # --- Discord (사후 대응 알림) ---
    discord_webhook_url: str | None = field(
        default_factory=lambda: os.getenv("DISCORD_WEBHOOK_URL")
    )
    # --- 로깅/스토리지 ---
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    incident_storage_path: Path = field(
        default_factory=lambda: Path(os.getenv("INCIDENT_STORAGE_PATH", "./incidents"))
    )
    blocklist_path: Path = field(
        default_factory=lambda: Path(os.getenv("BLOCKLIST_PATH", "./incidents/blocklist.json"))
    )
    # --- 차단 TTL(초) ---
    default_block_duration: int = field(default_factory=lambda: _int("DEFAULT_BLOCK_DURATION", 60))
    critical_block_duration: int = field(
        default_factory=lambda: _int("CRITICAL_BLOCK_DURATION", 120)
    )
    # --- 차단 모드 + 안전장치 ---
    block_mode: str = field(default_factory=lambda: os.getenv("BLOCK_MODE", "simulation"))
    allowlist_ips: list[str] = field(default_factory=lambda: _csv("ALLOWLIST_IPS"))
    # 사설/루프백 IP 는 기본적으로 절대 차단하지 않음(개발망 오차단 방지). 필요시 명시적으로 켠다.
    block_private_ips: bool = field(default_factory=lambda: _bool("BLOCK_PRIVATE_IPS", False))
    # --- nginx 모드 ---
    nginx_deny_file: Path = field(
        default_factory=lambda: Path(os.getenv("NGINX_DENY_FILE", "./incidents/deny.conf"))
    )
    nginx_reload_cmd: str = field(
        default_factory=lambda: os.getenv("NGINX_RELOAD_CMD", "nginx -s reload")
    )
    # --- aws_waf 모드 ---
    aws_region: str | None = field(default_factory=lambda: os.getenv("AWS_REGION"))
    waf_ipset_id: str | None = field(default_factory=lambda: os.getenv("WAF_IPSET_ID"))
    waf_ipset_name: str | None = field(default_factory=lambda: os.getenv("WAF_IPSET_NAME"))
    waf_scope: str = field(default_factory=lambda: os.getenv("WAF_SCOPE", "REGIONAL"))

    def __post_init__(self) -> None:
        if self.block_mode not in BLOCK_MODES:
            raise ValueError(
                f"BLOCK_MODE '{self.block_mode}' 는 허용되지 않음. 하나 선택: {BLOCK_MODES}"
            )

    @property
    def discord_enabled(self) -> bool:
        url = self.discord_webhook_url
        return bool(url) and _PLACEHOLDER_MARK not in url

    def duration_for(self, severity: str) -> int:
        """등급별 차단 TTL(초). CRITICAL 은 더 길게(.env CRITICAL_BLOCK_DURATION)."""
        return self.critical_block_duration if severity == "CRITICAL" else self.default_block_duration

    def is_allowlisted(self, ip: str | None) -> bool:
        """allowlist(정확 IP 또는 CIDR) 또는 사설/루프백(보호 시) 이면 차단 예외."""
        if not ip:
            return True  # IP 없는 인시던트는 네트워크 차단 대상 아님
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # 파싱 불가한 값은 안전하게 차단하지 않음
        if not self.block_private_ips and _is_protected(addr):
            return True
        for entry in self.allowlist_ips:
            try:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                if ip == entry:
                    return True
        return False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
