"""IR 파이프라인 — 수신 이벤트를 대응까지 한 흐름으로 처리.

  normalize(detector) → assess(analyzer) → block(responder) → save(store) → notify(notifier)

FastAPI 와 CLI/테스트가 공유하는 순수 로직. 의존성을 주입받아 테스트가 쉽다.
"""
from __future__ import annotations

from dataclasses import asdict

from config.settings import Settings, get_settings
from ir.analyzer.risk import assess
from ir.detector.normalize import normalize
from ir.notifier.discord import DiscordNotifier
from ir.responder.ip_blocker import IpBlocker
from ir.store.incident_store import IncidentStore


class IRPipeline:
    def __init__(self, settings: Settings | None = None,
                 blocker: IpBlocker | None = None,
                 store: IncidentStore | None = None,
                 notifier: DiscordNotifier | None = None):
        self.settings = settings or get_settings()
        self.blocker = blocker or IpBlocker(self.settings)
        self.store = store or IncidentStore(self.settings.incident_storage_path)
        self.notifier = notifier or DiscordNotifier(self.settings)

    def handle(self, raw: dict) -> dict:
        incident = normalize(raw)
        assessment = assess(incident, self.settings)
        result = self.blocker.block(incident, assessment)
        notified = self.notifier.notify_response(incident, assessment, result)

        risk = {"score": assessment.score, "severity": assessment.severity.value,
                "block_seconds": assessment.block_seconds}
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
