"""IR 파이프라인 — 수신 이벤트를 대응까지 한 흐름으로 처리.

  normalize(detector) → assess(analyzer) → block(responder) → save(store) → notify(notifier)

FastAPI 와 CLI/테스트가 공유하는 순수 로직. 의존성을 주입받아 테스트가 쉽다.
"""
from __future__ import annotations

from dataclasses import asdict

from config.settings import Settings, get_settings
from ir.analyzer.context import RiskContext
from ir.analyzer.risk import RiskAnalyzer
from ir.detector.normalize import normalize
from ir.notifier.discord import DiscordNotifier
from ir.responder.ip_blocker import IpBlocker
from ir.store.incident_store import IncidentStore
from ir.store.stats import StatsIndex


class IRPipeline:
    def __init__(
        self,
        settings: Settings | None = None,
        analyzer: RiskAnalyzer | None = None,
        blocker: IpBlocker | None = None,
        store: IncidentStore | None = None,
        notifier: DiscordNotifier | None = None,
    ):
        self.settings = settings or get_settings()
        self.blocker = blocker or IpBlocker(self.settings)
        self.notifier = notifier or DiscordNotifier(self.settings)
        # store: StatsIndex 를 기본 주입 — 테스트는 store= 로 교체 가능
        if store is not None:
            self.store = store
        else:
            meta = StatsIndex(
                self.settings.incident_meta_path,
                timezone=self.settings.service_timezone,
            )
            self.store = IncidentStore(
                self.settings.incident_storage_path,
                stats=meta,
            )
        # analyzer 는 blocker.store(BlockStore) 를 재범 장기 신호로 주입
        # analyzer=None 이면 RiskAnalyzer 기본 생성 — 기존 IRPipeline(settings) 호출 유지
        self.analyzer = analyzer or RiskAnalyzer(
            settings=self.settings,
            block_store=self.blocker.store,
        )

    def handle(self, raw: dict) -> dict:
        incident = normalize(raw)
        ctx = RiskContext.from_incident(incident)
        assessment = self.analyzer.assess(incident, ctx)
        result = self.blocker.block(incident, assessment)
        notified = self.notifier.notify_response(incident, assessment, result)

        risk = {
            "score": assessment.score,
            "severity": assessment.severity.value,
            "base_score": assessment.base_score,
            "base_severity": assessment.base_severity.value,
            "block_seconds": assessment.block_seconds,
        }
        response = {**{k: (v.value if hasattr(v, "value") else v)
                       for k, v in asdict(result).items()},
                    "enforced": result.enforced}
        self.store.save(incident, risk=risk, response=response, notified=notified)

        return {
            "incidentId": incident.id,
            "type": incident.type,
            "risk": risk,
            "response": response,
            "notified": notified,
        }
