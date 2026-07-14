"""인시던트 통계·인덱스 (StatsIndex) + 원자적 쓰기 검증."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from ir.models.incident import Incident
from ir.store._atomic import atomic_write_json, meta_lock
from ir.store.incident_store import IncidentStore
from ir.store.stats import StatsIndex, _MAX_IDS_PER_KEY


@pytest.fixture
def meta_dir(tmp_path: Path) -> Path:
    d = tmp_path / "incident_meta"
    d.mkdir()
    return d


@pytest.fixture
def index(meta_dir: Path) -> StatsIndex:
    return StatsIndex(meta_dir, timezone="Asia/Seoul")


# ── atomic ───────────────────────────────────────────────────

def test_atomic_write_roundtrip(tmp_path: Path):
    path = tmp_path / "x.json"
    atomic_write_json(path, {"a": 1})
    import json
    assert json.loads(path.read_text(encoding="utf-8")) == {"a": 1}


def test_atomic_no_flock_warns_once(meta_dir: Path, monkeypatch, caplog):
    import ir.store._atomic as atomic

    monkeypatch.setattr(atomic, "_HAS_FLOCK", False)
    monkeypatch.setattr(atomic, "_warned_no_flock", False)
    with caplog.at_level("WARNING", logger="ir.store.atomic"):
        with meta_lock(meta_dir):
            pass
        first = len(caplog.records)
        with meta_lock(meta_dir):
            pass
        second = len(caplog.records)
    assert first >= 1
    assert second == first
    assert "fcntl" in caplog.text


# ── stats / hour TZ ──────────────────────────────────────────

def test_record_updates_by_type_and_hour(index: StatsIndex):
    # 계약 경로: naive 14:00 → 서비스 TZ(Seoul)로 간주 → hour 14
    index.record(
        incident_id="a1",
        attack_type="SQLI_ATTEMPT",
        client_ip="203.0.113.1",
        occurred_at=datetime(2026, 7, 3, 14, 0, 0),
    )
    s = index.stats()
    assert s.by_type["SQLI_ATTEMPT"] == 1
    assert s.by_hour["14"] == 1
    assert s.total == 1


def test_hour_key_aware_utc_defense(index: StatsIndex):
    """계약 외 aware 입력 방어 — UTC → Asia/Seoul 변환.

    백엔드 IrForwarder 는 naive 만 보내지만, aware 가 들어오면 astimezone 한다.
    """
    from datetime import timezone as tz

    # UTC 15:00 → Seoul 00:00 (다음날, hour 00)
    index.record(
        incident_id="utc-15",
        attack_type="ANOMALY_SCAN",
        client_ip="203.0.113.1",
        occurred_at=datetime(2026, 7, 3, 15, 0, 0, tzinfo=tz.utc),
    )
    assert index.stats().by_hour["00"] == 1

    # UTC 06:00 → Seoul 15:00
    index.record(
        incident_id="utc-06",
        attack_type="ANOMALY_SCAN",
        client_ip="203.0.113.2",
        occurred_at=datetime(2026, 7, 3, 6, 0, 0, tzinfo=tz.utc),
    )
    assert index.stats().by_hour["15"] == 1


def test_stats_timezone_meta_field(index: StatsIndex):
    index.record(
        incident_id="t1",
        attack_type="XSS_ATTEMPT",
        client_ip=None,
        occurred_at=None,
    )
    s = index.stats()
    assert s.timezone == "Asia/Seoul"
    assert "timezone" in index.stats_dict()


def test_index_by_ip_append_and_trim_1000(index: StatsIndex):
    ip = "203.0.113.9"
    for i in range(_MAX_IDS_PER_KEY + 1):
        index.record(
            incident_id=f"id-{i}",
            attack_type="ANOMALY_SCAN",
            client_ip=ip,
            occurred_at=datetime(2026, 7, 3, 10, 0, 0),
        )
    import json
    raw = json.loads((index.meta_dir / "index_by_ip.json").read_text(encoding="utf-8"))
    assert len(raw[ip]) == _MAX_IDS_PER_KEY
    assert raw[ip][0] == "id-1"          # 가장 오래된 id-0 eviction
    assert raw[ip][-1] == f"id-{_MAX_IDS_PER_KEY}"


def test_index_by_type_trim_1000(index: StatsIndex):
    for i in range(_MAX_IDS_PER_KEY + 1):
        index.record(
            incident_id=f"t-{i}",
            attack_type="XSS_ATTEMPT",
            client_ip=f"203.0.113.{i % 50}",
            occurred_at=datetime(2026, 7, 3, 11, 0, 0),
        )
    import json
    raw = json.loads((index.meta_dir / "index_by_type.json").read_text(encoding="utf-8"))
    assert len(raw["XSS_ATTEMPT"]) == _MAX_IDS_PER_KEY


def test_find_by_ip(index: StatsIndex, tmp_path: Path):
    store = IncidentStore(tmp_path / "incidents", stats=index)
    inc = Incident.model_validate({
        "id": "find-ip-1",
        "type": "SQLI_ATTEMPT",
        "clientIp": "203.0.113.50",
        "createdAt": "2026-07-03T10:00:00",
    })
    store.save(inc, risk={"score": 95}, response={"enforced": True}, notified=False)
    found = store.find(ip="203.0.113.50")
    assert len(found) == 1
    assert found[0]["incident"]["id"] == "find-ip-1"


def test_find_by_type(index: StatsIndex, tmp_path: Path):
    store = IncidentStore(tmp_path / "incidents", stats=index)
    store.save(
        Incident.model_validate({
            "id": "ft-1", "type": "XSS_ATTEMPT", "clientIp": "203.0.113.1",
            "createdAt": "2026-07-03T10:00:00",
        }),
        risk={"score": 75}, response={}, notified=False,
    )
    assert len(store.find(type="XSS_ATTEMPT")) == 1


def test_find_intersection_ip_and_type(index: StatsIndex, tmp_path: Path):
    store = IncidentStore(tmp_path / "incidents", stats=index)
    store.save(
        Incident.model_validate({
            "id": "both-1", "type": "SQLI_ATTEMPT", "clientIp": "203.0.113.7",
            "createdAt": "2026-07-03T10:00:00",
        }),
        risk={}, response={}, notified=False,
    )
    store.save(
        Incident.model_validate({
            "id": "ip-only", "type": "XSS_ATTEMPT", "clientIp": "203.0.113.7",
            "createdAt": "2026-07-03T11:00:00",
        }),
        risk={}, response={}, notified=False,
    )
    found = store.find(ip="203.0.113.7", type="SQLI_ATTEMPT")
    assert [r["incident"]["id"] for r in found] == ["both-1"]


def test_top_ips_limited_to_20(index: StatsIndex):
    for i in range(25):
        index.record(
            incident_id=f"top-{i}",
            attack_type="ANOMALY_SCAN",
            client_ip=f"198.51.100.{i}",
            occurred_at=datetime(2026, 7, 3, 12, 0, 0),
        )
    s = index.stats()
    assert len(s.top_ips) == 20
    # _ip_counts 는 25개 유지 (공개 stats_dict 에는 없음)
    assert "_ip_counts" not in index.stats_dict()
    import json
    raw = json.loads((index.meta_dir / "stats.json").read_text(encoding="utf-8"))
    assert len(raw["_ip_counts"]) == 25


def test_save_hooks_stats_via_store(index: StatsIndex, tmp_path: Path):
    store = IncidentStore(tmp_path / "inc", stats=index)
    store.save(
        Incident.model_validate({
            "id": "hook-1", "type": "IDOR_ATTEMPT", "clientIp": "203.0.113.2",
            "createdAt": "2026-07-03T09:00:00",
        }),
        risk={"score": 80}, response={"enforced": True}, notified=False,
    )
    assert index.stats().by_type["IDOR_ATTEMPT"] == 1


def test_recent_unchanged_ignores_meta(index: StatsIndex, tmp_path: Path):
    """meta 는 형제 디렉터리 — recent() 가 meta json 을 읽지 않음."""
    inc_dir = tmp_path / "incidents"
    store = IncidentStore(inc_dir, stats=index)
    store.save(
        Incident.model_validate({
            "id": "r1", "type": "XSS_ATTEMPT", "clientIp": "203.0.113.3",
            "createdAt": "2026-07-03T10:00:00",
        }),
        risk={}, response={}, notified=False,
    )
    # meta 에 파일이 생겨도 recent 는 incidents/ 만
    assert (index.meta_dir / "stats.json").exists()
    recent = store.recent()
    assert len(recent) == 1
    assert recent[0]["incident"]["id"] == "r1"


def test_find_without_stats_returns_empty(tmp_path: Path):
    store = IncidentStore(tmp_path / "inc", stats=None)
    assert store.find(ip="1.2.3.4") == []
    assert store.stats_snapshot() is None


def test_lock_timeout_skips_index_update(meta_dir: Path, tmp_path: Path, monkeypatch, caplog):
    """fcntl.flock mock — 실제 OS 락은 검증하지 않음. timeout 로직만 검증."""
    import ir.store._atomic as atomic

    monkeypatch.setattr(atomic, "_HAS_FLOCK", True)
    monkeypatch.setattr(atomic, "_LOCK_TIMEOUT_SECONDS", 0.12)
    monkeypatch.setattr(atomic, "_LOCK_RETRY_INTERVAL", 0.03)

    class _FakeFcntl:
        LOCK_EX = 2
        LOCK_NB = 4
        LOCK_UN = 8

        @staticmethod
        def flock(fd, op):
            if op == _FakeFcntl.LOCK_UN:
                return
            raise BlockingIOError()

    monkeypatch.setattr(atomic, "fcntl", _FakeFcntl)

    index = StatsIndex(meta_dir, timezone="Asia/Seoul")
    store = IncidentStore(tmp_path / "incidents", stats=index)
    with caplog.at_level("WARNING", logger="ir.store.stats"):
        store.save(
            Incident.model_validate({
                "id": "lock-skip-1",
                "type": "XSS_ATTEMPT",
                "clientIp": "203.0.113.9",
                "createdAt": "2026-07-03T10:00:00",
            }),
            risk={}, response={}, notified=False,
        )
    # 원본 json 보존
    assert (tmp_path / "incidents" / "lock-skip-1.json").exists()
    # 인덱스 미갱신
    assert not (meta_dir / "stats.json").exists()
    assert "lock timeout" in caplog.text.lower() or "index lock timeout" in caplog.text


def test_lock_acquired_within_timeout(meta_dir: Path, monkeypatch):
    """재시도 후 획득 성공 — flock mock (실제 OS 락 미검증)."""
    import ir.store._atomic as atomic

    monkeypatch.setattr(atomic, "_HAS_FLOCK", True)
    monkeypatch.setattr(atomic, "_LOCK_TIMEOUT_SECONDS", 1.0)
    monkeypatch.setattr(atomic, "_LOCK_RETRY_INTERVAL", 0.02)

    state = {"n": 0}

    class _FakeFcntl:
        LOCK_EX = 2
        LOCK_NB = 4
        LOCK_UN = 8

        @staticmethod
        def flock(fd, op):
            if op == _FakeFcntl.LOCK_UN:
                return
            state["n"] += 1
            if state["n"] < 3:
                raise BlockingIOError()
            # 3번째부터 성공 (no-op acquire)

    monkeypatch.setattr(atomic, "fcntl", _FakeFcntl)

    index = StatsIndex(meta_dir, timezone="Asia/Seoul")
    index.record(
        incident_id="retry-ok",
        attack_type="SQLI_ATTEMPT",
        client_ip="203.0.113.1",
        occurred_at=datetime(2026, 7, 3, 10, 0, 0),
    )
    assert index.stats().total == 1
    assert state["n"] >= 3


def test_find_lock_timeout_returns_empty(meta_dir: Path, monkeypatch, caplog):
    """find() 타임아웃 → [] + warning (실제 OS 락 미검증)."""
    import ir.store._atomic as atomic

    monkeypatch.setattr(atomic, "_HAS_FLOCK", True)
    monkeypatch.setattr(atomic, "_LOCK_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(atomic, "_LOCK_RETRY_INTERVAL", 0.03)

    class _FakeFcntl:
        LOCK_EX = 2
        LOCK_NB = 4
        LOCK_UN = 8

        @staticmethod
        def flock(fd, op):
            if op == _FakeFcntl.LOCK_UN:
                return
            raise BlockingIOError()

    monkeypatch.setattr(atomic, "fcntl", _FakeFcntl)
    index = StatsIndex(meta_dir, timezone="Asia/Seoul")
    with caplog.at_level("WARNING", logger="ir.store.stats"):
        assert index.find(ip="1.2.3.4") == []
    assert "lock timeout" in caplog.text.lower() or "index lock timeout" in caplog.text
