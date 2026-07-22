"""IP 차단 오케스트레이션 — 사후(2차) 대응의 핵심.

앱(Java)이 이미 1차 즉시 차단(가드 arming)을 하므로, IR 모듈은 **지속형 IP 차단**을
담당한다. 안전을 위해:
  1) reconcile 로 만료분 먼저 해제(룰 무한누적 방지)
  2) allowlist / 사설·루프백 IP 는 차단 제외(개발망 오차단 방지)
  3) 멱등성 — 이미 활성 차단이면 재집행·재알림 없이 TTL 만 재무장(rearm)
  4) 등급 기반 — LOW 는 차단하지 않고 기록/알림만
  5) 재범(hits) 기반 TTL escalation — 상한 ×24(하루 격리 캡)

모드 분기(simulation 기본 / nginx / aws_waf)는 핸들러로 캡슐화. simulation 은
실제 네트워크를 건드리지 않는다.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum

from config.settings import Settings, get_settings
from ir.analyzer.risk import RiskAssessment
from ir.models.incident import Incident
from ir.responder.blocklist import BlockEntry, BlockStore
from ir.responder.handlers.base import BlockHandler
from ir.responder.handlers.simulation import SimulationHandler

log = logging.getLogger("ir.responder.ip_blocker")

# 재범(hits) → TTL 배수 임계값 (모듈 private)
_ESCALATION_HITS_X2 = 3
_ESCALATION_HITS_X4 = 5
_ESCALATION_HITS_X24 = 10


def _escalated_ttl(base_ttl: int, hits: int) -> int:
    """재범(hits) 기반 TTL 배수. 상한 ×24 (하루 격리 캡).

    시맨틱: **재무장(rearm)** — 활성 중 재차단 시 남은 TTL 을 이어 붙이지 않고
    ``expires_at = now + escalated_ttl`` 로 덮어쓴다.
    (누적 연장 ``남은 + 새TTL`` 이 아님. BlockStore.upsert 와 동일.)

    임계값:
      - hits >= 3  → base × 2
      - hits >= 5  → base × 4
      - hits >= 10 → base × 24 (상한; hits=50 이어도 ×24)

    hits 계산 시점:
      - 활성 중 재차단(EXTENDED): 누적 증가 (existing.hits + 1)
      - TTL 만료 후 재차단(BLOCKED): 1로 리셋
        └ 이유: block() 흐름에서 prune() → get() 순서라 만료 엔트리는 삭제 후 조회됨
        └ 만료 후 이력 영속화는 prune 정책 변경 필요 (별도 티켓)

    Args:
        base_ttl: 등급별 기본 TTL(초). RiskAssessment.block_seconds.
        hits: 이번 차단 이후 누적 횟수(next_hits). upsert 가 기록할 hits 와 동일해야 함.

    Returns:
        escalated TTL(초) — upsert 에 넘겨 재무장에 사용.
    """
    if hits >= _ESCALATION_HITS_X24:
        return base_ttl * 24
    if hits >= _ESCALATION_HITS_X4:
        return base_ttl * 4
    if hits >= _ESCALATION_HITS_X2:
        return base_ttl * 2
    return base_ttl


class BlockAction(str, Enum):
    BLOCKED = "BLOCKED"           # 신규 차단 집행
    EXTENDED = "EXTENDED"         # 이미 차단 중 → TTL 재무장(멱등; 액션명 호환 유지)
    SKIPPED_ALLOWLIST = "SKIPPED_ALLOWLIST"  # allowlist/사설IP 예외
    SKIPPED_LOW = "SKIPPED_LOW"   # 저위험 → 차단 안 함(기록/알림만)
    SKIPPED_NO_IP = "SKIPPED_NO_IP"


@dataclass(frozen=True)
class BlockResult:
    action: BlockAction
    ip: str | None
    mode: str
    ttl_seconds: int = 0
    hits: int = 0

    @property
    def enforced(self) -> bool:
        return self.action in (BlockAction.BLOCKED, BlockAction.EXTENDED)


def build_handler(settings: Settings) -> BlockHandler:
    """설정의 block_mode 에 맞는 핸들러를 생성."""
    mode = settings.block_mode
    if mode == "simulation":
        return SimulationHandler()
    if mode == "nginx":
        from ir.responder.handlers.nginx import NginxHandler
        return NginxHandler(settings.nginx_deny_file, settings.nginx_reload_cmd)
    if mode == "aws_waf":
        from ir.responder.handlers.aws_waf import AwsWafHandler
        return AwsWafHandler(
            region=settings.aws_region, ipset_id=settings.waf_ipset_id,
            ipset_name=settings.waf_ipset_name, scope=settings.waf_scope,
        )
    raise ValueError(f"알 수 없는 block_mode: {mode}")


class IpBlocker:
    def __init__(self, settings: Settings | None = None,
                 store: BlockStore | None = None,
                 handler: BlockHandler | None = None):
        self.settings = settings or get_settings()
        self.store = store or BlockStore(self.settings.blocklist_path)
        self.handler = handler or build_handler(self.settings)

    def reconcile(self, now: float | None = None) -> list[BlockEntry]:
        """만료분 제거 + 현재 활성 목록을 핸들러에 재선언. 반환: 해제된 목록."""
        now = time.time() if now is None else now
        expired = self.store.prune(now)
        self.handler.apply(self.store.active(now))
        if expired:
            log.info("[IR] TTL 만료 해제 %d건: %s", len(expired), [e.ip for e in expired])
        return expired

    def block(self, incident: Incident, assessment: RiskAssessment,
              now: float | None = None) -> BlockResult:
        now = time.time() if now is None else now
        mode = self.settings.block_mode

        # 0) 매 요청마다 만료 정리(별도 스케줄러 없이도 자연 해제)
        self.store.prune(now)

        ip = incident.client_ip
        if not ip:
            self._sync(now)
            return BlockResult(BlockAction.SKIPPED_NO_IP, None, mode)

        # 1) 저위험은 차단하지 않음(기록/알림만)
        if not assessment.should_block:
            self._sync(now)
            return BlockResult(BlockAction.SKIPPED_LOW, ip, mode)

        # 2) allowlist/사설·루프백 예외 — 실수로 개발망을 막지 않는다
        if self.settings.is_allowlisted(ip):
            log.info("[IR] 차단 예외(allowlist/사설IP): %s", ip)
            self._sync(now)
            return BlockResult(BlockAction.SKIPPED_ALLOWLIST, ip, mode)

        # 3) 재범 기반 TTL escalation 후 멱등 등록/재무장(rearm)
        #    prune() 직후이므로 get() 결과는 활성 엔트리만(이중으로 is_active 방어).
        #    next_hits 는 upsert 가 기록할 hits 와 동일해야 TTL·hits 가 어긋나지 않음.
        existing = self.store.get(ip)
        next_hits = (
            existing.hits + 1
            if (existing is not None and existing.is_active(now))
            else 1
        )
        ttl = _escalated_ttl(assessment.block_seconds, next_hits)
        entry, is_new = self.store.upsert(
            ip,
            reason=incident.type,
            severity=assessment.base_severity.value,
            mode=mode,
            incident_id=incident.ensure_id(),
            ttl_seconds=ttl,
            now=now,
        )
        # 4) 현재 활성 집합을 핸들러에 선언(집행)
        self.handler.apply(self.store.active(now))

        action = BlockAction.BLOCKED if is_new else BlockAction.EXTENDED
        log.info(
            "[IR] IP %s %s (mode=%s ttl=%ds hits=%d escalated_ttl=%ds)",
            ip, action.value, mode, entry.remaining(now), entry.hits, ttl,
        )
        return BlockResult(action, ip, mode, ttl_seconds=entry.remaining(now), hits=entry.hits)

    def _sync(self, now: float) -> None:
        """차단 집행이 없더라도 활성 상태를 핸들러에 재선언(만료 반영)."""
        self.handler.apply(self.store.active(now))
