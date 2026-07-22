"""위험도 분석 — 앱 `com.shop.air.RiskScoring` 을 그대로 포팅.

**base parity / effective divergence (하이브리드 정책)**:
    - ``base_score`` / ``base_severity``: 유형(type) 기준 — 앱 RiskScoring SSOT 와 1:1.
    - ``score`` / ``severity``: 컨텍스트 가중 반영 effective (기록·관측·Embed용).
    - **외부 에스컬레이션·차단 게이트**는 base 기준:
        · Discord CRITICAL 전용 웹훅 → ``base_severity == CRITICAL`` 일 때만
        · ``should_block`` / ``block_seconds`` → ``base_severity`` (앱과 최대 정합)

컨텍스트 스코어링 확장:
    base score 위에 endpoint/payload/재범/시간대 가중치를 얹어 effective [0,100] 산출.
    - 함수형 API: assess_with_context(incident, ctx, settings=None)
    - 클래스형 API: RiskAnalyzer(...).assess(incident, ctx)
    - ctx=None 이면 base == effective (하위 호환).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

from config.settings import Settings, get_settings
from ir.analyzer import rules as _rules
from ir.analyzer.context import RecidivismTracker, RiskContext
from ir.models.incident import Incident, Severity

_logger = logging.getLogger("ir.analyzer.risk")

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
    """analyzer 산출물 — responder/notifier 가 소비.

    base_* 는 앱 RiskScoring parity; score/severity 는 컨텍스트 가중 effective.
    차단·TTL·CRITICAL 웹훅은 base_* 로 게이트한다.
    """

    base_score: int
    base_severity: Severity
    score: int  # effective (컨텍스트 가중)
    severity: Severity  # effective
    block_seconds: int  # base_severity 기준 TTL(초)

    @property
    def should_block(self) -> bool:
        # MEDIUM 이상만 네트워크 차단(LOW 는 기록/알림만) — base 기준(앱 정합)
        return self.base_severity in (
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
        )


def _make_assessment(
    *,
    base_score: int,
    effective_score: int,
    settings: Settings,
) -> RiskAssessment:
    base_sev = _severity_from_score(base_score)
    effective_sev = _severity_from_score(effective_score)
    return RiskAssessment(
        base_score=base_score,
        base_severity=base_sev,
        score=effective_score,
        severity=effective_sev,
        block_seconds=settings.duration_for(base_sev.value),
    )


def assess(incident: Incident, settings: Settings | None = None) -> RiskAssessment:
    settings = settings or get_settings()
    base = score(incident.type)
    return _make_assessment(base_score=base, effective_score=base, settings=settings)


# ─────────────────────────────────────────────────────────────
# 이하 컨텍스트 스코어링 확장
# ─────────────────────────────────────────────────────────────

def _severity_from_score(s: int) -> Severity:
    """
    최종 점수(컨텍스트 가중 반영 후) 로 severity 재판정.

    기존 severity(attack_type) 는 유형만 보고 판정하므로,
    컨텍스트 가중이 반영된 점수를 등급에 재매핑하려면 별도 함수가 필요.
    임계값은 기존 severity() 와 동일하게 유지.
    """
    if s >= 90:
        return Severity.CRITICAL
    if s >= 70:
        return Severity.HIGH
    if s >= 40:
        return Severity.MEDIUM
    return Severity.LOW


def _time_weight(occurred_at: datetime | None, settings: Settings) -> int:
    """
    야간 시간대(서비스 타임존 기준) 여부에 따라 가중치.

    - occurred_at 이 naive datetime 이면 서비스 타임존으로 간주.
      (앱 IrForwarder: LocalDateTime + ISO_LOCAL_DATE_TIME → naive ISO)
    - aware datetime 이면 서비스 타임존으로 변환 후 판정.
    - occurred_at is None → 0 (판정 근거 부족 → 보수적; stats 의 now(tz) 와 다름).
    - 잘못된 tz 문자열이면 안전하게 0 반환 (설정 오타로 스코어링 죽지 않게).
    """
    if occurred_at is None:
        return 0  # 판정 근거 부족 → 0점 (보수적)
    try:
        tz = ZoneInfo(settings.service_timezone)
    except Exception:
        _logger.warning(
            "invalid service_timezone=%r, skip time_weight",
            getattr(settings, "service_timezone", None),
        )
        return 0

    local = (
        occurred_at.replace(tzinfo=tz)
        if occurred_at.tzinfo is None
        else occurred_at.astimezone(tz)
    )
    if settings.night_hours_start <= local.hour < settings.night_hours_end:
        return _rules.NIGHT_WEIGHT
    return 0


def assess_with_context(
    incident: Incident,
    ctx: RiskContext | None = None,
    *,
    settings: Settings | None = None,
) -> RiskAssessment:
    """
    컨텍스트 가중치를 반영한 스코어링 (함수형 API).

    - ctx=None 이면 base == effective (assess 와 동일).
    - effective: base + endpoint + payload + recidivism + time, [0,100] clamp.
    - base_score/base_severity: 유형(type)만 — 앱 parity.
    - 차단/TTL/CRITICAL 웹훅: base_severity 기준 (effective 로 승격되지 않음).
    - 재범 슬라이딩 윈도우는 RiskAnalyzer 클래스 경로에서 처리;
      block_hits 는 ctx 에 미리 담겨 있으면 반영.
    """
    settings = settings or get_settings()
    if ctx is None:
        return assess(incident, settings)

    base = score(incident.type)
    endpoint_w = _rules.match_endpoint_weight(ctx.endpoint)
    payload_w, matched = _rules.match_payload_weight(ctx.payload)
    recid_w = _rules.recidivism_weight(recent_hits=0, block_hits=ctx.block_hits)
    time_w = _time_weight(ctx.occurred_at, settings)

    total = _rules.clamp_score(base + endpoint_w + payload_w + recid_w + time_w)

    _logger.debug(
        "assess_with_context type=%s base=%d ep=+%d pl=+%d%s recid=+%d time=+%d => %d",
        incident.type, base, endpoint_w, payload_w,
        f"({','.join(matched)})" if matched else "",
        recid_w, time_w, total,
    )
    return _make_assessment(
        base_score=base, effective_score=total, settings=settings,
    )


class RiskAnalyzer:
    """
    컨텍스트 스코어링 오케스트레이터 (클래스 경로).

    - 인메모리 재범 트래커(RecidivismTracker) 를 인스턴스 필드로 소유.
    - BlockStore 를 주입받으면 block_hits(영속 누적) 도 반영.
    - assess(incident, ctx=None) 진입점 하나로 통일.
      ctx=None 이면 기존 assess() 로 위임 (하위 호환).

    Thread-safety:
    - RecidivismTracker / BlockStore 는 threading.Lock 으로 보호.
    - sync ingest(FastAPI threadpool) + reconcile(asyncio.to_thread) 동시 접근 안전.
    - 멀티프로세스 배포 시 슬라이딩 윈도우는 프로세스별 파편화되지만,
      BlockStore.hits(영속) 로 장기 신호는 커버됨.
    """

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        block_store=None,  # ir.responder.blocklist.BlockStore | None (순환 import 회피)
        tracker: RecidivismTracker | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._block_store = block_store
        self._tracker = tracker or RecidivismTracker()

    def assess(
        self,
        incident: Incident,
        ctx: RiskContext | None = None,
    ) -> RiskAssessment:
        """
        컨텍스트가 없으면 기존 함수형 assess() 결과 반환.
        컨텍스트가 있으면 재범 추적기 + BlockStore hits 까지 합산.
        """
        if ctx is None:
            return assess(incident, self._settings)

        base = score(incident.type)
        endpoint_w = _rules.match_endpoint_weight(ctx.endpoint)
        payload_w, matched = _rules.match_payload_weight(ctx.payload)

        # 재범: 슬라이딩 윈도우(단기) + BlockStore hits(장기)
        recent = 0
        if ctx.client_ip:
            recent = self._tracker.count(
                ctx.client_ip,
                self._settings.recidivism_window_seconds,
            )

        block_hits = ctx.block_hits
        if block_hits == 0 and self._block_store is not None and ctx.client_ip:
            entry = self._block_store.get(ctx.client_ip)
            if entry is not None:
                block_hits = getattr(entry, "hits", 0) or 0

        recid_w = _rules.recidivism_weight(
            recent_hits=recent,
            block_hits=block_hits,
        )
        time_w = _time_weight(ctx.occurred_at, self._settings)

        total = _rules.clamp_score(
            base + endpoint_w + payload_w + recid_w + time_w
        )
        assessment = _make_assessment(
            base_score=base, effective_score=total, settings=self._settings,
        )

        _logger.info(
            "risk.assess type=%s ip=%s base=%d ep=+%d pl=+%d%s "
            "recid=+%d(recent=%d,hits=%d) time=+%d => %d(%s, base=%s)",
            incident.type,
            ctx.client_ip or "-",
            base, endpoint_w, payload_w,
            f"({','.join(matched)})" if matched else "",
            recid_w, recent, block_hits, time_w,
            total, assessment.severity.value, assessment.base_severity.value,
        )

        # 기록은 스코어링 완료 후 — 같은 이벤트가 자기 자신을 재범으로 못 세게
        if ctx.client_ip:
            self._tracker.record(ctx.client_ip)

        return assessment

    @property
    def tracker(self) -> RecidivismTracker:
        """관측/테스트용 노출."""
        return self._tracker