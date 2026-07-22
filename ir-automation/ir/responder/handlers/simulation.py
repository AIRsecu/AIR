"""simulation 핸들러 — 실제 네트워크는 건드리지 않고 로그만 남긴다.

기본값. 데모/로컬/CI 에서 실 IP 를 막지 않고 파이프라인 전체를 안전하게 검증한다.
차단 '집행'은 하지 않지만, 어떤 IP 가 차단될 것인지는 BlockStore(JSON)에 그대로 남아
대시보드/데모에서 확인할 수 있다.
"""
from __future__ import annotations

import logging

from ir.responder.blocklist import BlockEntry
from ir.responder.handlers.base import BlockHandler

log = logging.getLogger("ir.responder.simulation")


class SimulationHandler(BlockHandler):
    name = "simulation"

    def apply(self, active: list[BlockEntry]) -> None:
        ips = [e.ip for e in active]
        log.info("[SIM] 차단 시뮬레이션 — 현재 활성 차단 %d건: %s", len(ips), ips or "(없음)")
