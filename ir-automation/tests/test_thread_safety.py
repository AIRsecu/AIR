"""스레드 안전 — sync ingest + asyncio.to_thread(reconcile) 동시 접근."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace

from config.settings import Settings

from ir.analyzer.context import RecidivismTracker, RiskContext
from ir.analyzer.risk import RiskAnalyzer, assess
from ir.models.incident import Incident
from ir.responder.blocklist import BlockStore
from ir.responder.ip_blocker import IpBlocker


def _incident(ip: str = "203.0.113.99") -> Incident:
    return Incident.model_validate({
        "type": "XSS_ATTEMPT",
        "clientIp": ip,
        "endpoint": "/api/v1/products/search",
        "payload": "ok",
        "createdAt": "2026-07-03T10:00:00",
    })


def test_recidivism_tracker_concurrent_record_count():
    tracker = RecidivismTracker(max_hits_per_ip=200, max_tracked_ips=50)
    errors: list[Exception] = []

    def worker(base: int) -> None:
        try:
            ip = f"10.0.{base // 256}.{base % 256}"
            for i in range(50):
                now = float(base * 50 + i)
                tracker.record(ip, now=now)
                tracker.count(ip, window_seconds=3600, now=now)
        except Exception as e:
            errors.append(e)

    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(worker, range(16)))

    assert not errors
    assert len(tracker) <= 50


def test_blockstore_concurrent_upsert_prune_active(settings, tmp_path):
    path = tmp_path / "blocklist-thread.json"
    store = BlockStore(path)
    errors: list[Exception] = []
    lock = threading.Lock()
    now_base = 10_000.0

    def ingest_worker(n: int) -> None:
        try:
            ip = f"198.51.100.{n % 250 + 1}"
            store.upsert(
                ip,
                reason="XSS_ATTEMPT",
                severity="HIGH",
                mode="simulation",
                incident_id=f"id-{n}",
                ttl_seconds=120,
                now=now_base + n,
            )
            store.get(ip)
            store.active(now=now_base + n)
        except Exception as e:
            with lock:
                errors.append(e)

    def reconcile_worker() -> None:
        try:
            for t in range(20):
                store.prune(now=now_base + t * 5)
                store.active(now=now_base + t * 5)
        except Exception as e:
            with lock:
                errors.append(e)

    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(ingest_worker, i) for i in range(30)]
        futs += [ex.submit(reconcile_worker) for _ in range(4)]
        for f in as_completed(futs):
            f.result()

    assert not errors
    assert path.exists()


def test_pipeline_ingest_and_reconcile_concurrent(settings, tmp_path):
    """IpBlocker.block + reconcile 동시 호출 — 예외 없이 완료."""
    cfg = replace(
        settings,
        blocklist_path=tmp_path / "bl-concurrent.json",
        incident_storage_path=tmp_path / "incidents",
        incident_meta_path=tmp_path / "meta.json",
    )
    blocker = IpBlocker(cfg)
    inc = _incident()
    a = assess(inc, cfg)
    errors: list[Exception] = []
    now = 20_000.0

    def ingest() -> None:
        try:
            for i in range(15):
                blocker.block(inc, a, now=now + i)
        except Exception as e:
            errors.append(e)

    def reconcile() -> None:
        try:
            for i in range(15):
                blocker.reconcile(now=now + i)
        except Exception as e:
            errors.append(e)

    threads = [
        threading.Thread(target=ingest),
        threading.Thread(target=reconcile),
        threading.Thread(target=ingest),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors


def test_risk_analyzer_concurrent_assess(settings):
    analyzer = RiskAnalyzer(settings=settings)
    inc = _incident()
    ctx = RiskContext.from_incident(inc)
    scores: list[int] = []
    lock = threading.Lock()

    def worker() -> None:
        for _ in range(20):
            s = analyzer.assess(inc, ctx).score
            with lock:
                scores.append(s)

    with ThreadPoolExecutor(max_workers=4) as ex:
        list(ex.map(lambda _: worker(), range(4)))

    assert scores  # all completed without crash
