"""테스트 공용 픽스처 — 임시 스토리지 + simulation 모드 + Discord 비활성 설정."""
from __future__ import annotations

import pytest

from config.settings import Settings


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        discord_webhook_url=None,          # 알림 전송 안 함(네트워크 격리)
        block_mode="simulation",           # 실 IP 안 건드림
        incident_storage_path=tmp_path / "incidents",
        blocklist_path=tmp_path / "incidents" / "blocklist.json",
        default_block_duration=60,
        critical_block_duration=120,
        allowlist_ips=["10.0.0.5", "192.168.100.0/24"],
        block_private_ips=False,
    )
