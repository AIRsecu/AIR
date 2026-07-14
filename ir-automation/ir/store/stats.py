"""인시던트 통계·인덱스 — ``incident_meta/`` 형제 디렉터리.

파일:
  stats.json         timezone/total/by_type/by_hour/top_ips/_ip_counts/updated_at
  index_by_ip.json   {ip: [id, ...]}    # IP당 최근 1000
  index_by_type.json {type: [id, ...]}  # type당 최근 1000

incremental: ``record()`` 마다 append + counter.
인덱스는 검색용(최근 1000). ``_ip_counts`` 는 trim 과 무관한 누적 카운터(top_ips 정확도).

기동 시 동작:
  StatsIndex.__init__ 은 경로만 설정한다. incidents/*.json 을 재스캔하지 않는다.
  디스크에 남은 incident_meta/*.json 이 있으면 이후 load 시 그대로 사용하고,
  meta 를 지우고 재기동하면 빈 상태로 시작해 이후 record() 만 반영된다.

락 타임아웃 복구 (수동):
  락 타임아웃(기본 2초) 시 해당 인시던트는 stats/index 에서 누락될 수 있다.
  원본 incidents/<id>.json 은 정상 저장된다.
  자동 재구성 API(rebuild) 는 없다(후속 티켓).
  수동: IR 정지 → incident_meta/ 삭제 → 재기동
  (재기동만으로는 기존 <id>.json 이 인덱스로 복원되지 않음 — 이후 신규 record 만 반영).
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from ir.store._atomic import LockTimeout, atomic_write_json, meta_lock

log = logging.getLogger("ir.store.stats")

_MAX_IDS_PER_KEY = 1000
_TOP_IPS = 20


@dataclass(frozen=True)
class IncidentStats:
    timezone: str
    total: int
    by_type: dict[str, int]
    by_hour: dict[str, int]
    top_ips: list[dict[str, Any]]
    updated_at: str


def _empty_hours() -> dict[str, int]:
    return {f"{h:02d}": 0 for h in range(24)}


class StatsIndex:
    def __init__(
        self,
        meta_dir: Path,
        *,
        timezone: str = "Asia/Seoul",
        max_ids_per_key: int = _MAX_IDS_PER_KEY,
        top_ips_n: int = _TOP_IPS,
    ) -> None:
        # 경로만 설정 — incidents/*.json 재스캔/재구성 없음
        self.meta_dir = Path(meta_dir)
        self.timezone = timezone
        self.max_ids_per_key = max_ids_per_key
        self.top_ips_n = top_ips_n
        self._stats_path = self.meta_dir / "stats.json"
        self._by_ip_path = self.meta_dir / "index_by_ip.json"
        self._by_type_path = self.meta_dir / "index_by_type.json"

    def record(
        self,
        *,
        incident_id: str,
        attack_type: str,
        client_ip: str | None,
        occurred_at: datetime | None,
    ) -> None:
        """incremental 갱신. 락 타임아웃 시 skip (원본 incident json 은 이미 저장됨)."""
        try:
            with meta_lock(self.meta_dir):
                self._record_unlocked(
                    incident_id=incident_id,
                    attack_type=attack_type,
                    client_ip=client_ip,
                    occurred_at=occurred_at,
                )
        except LockTimeout:
            log.warning(
                "index lock timeout — skip stats/index update for id=%s "
                "(incident json 은 보존됨; meta 수동 삭제 후 재기동해도 "
                "기존 json 자동 재인덱싱 없음)",
                incident_id,
            )

    def find(
        self,
        *,
        ip: str | None = None,
        type: str | None = None,
        limit: int = 50,
    ) -> list[str]:
        """필터에 맞는 incident id (최신 우선). 둘 다 있으면 교집합.

        락 타임아웃 시 [] + warning (API 500 방지).
        """
        limit = max(1, limit)
        try:
            with meta_lock(self.meta_dir):
                by_ip = self._load_index_unlocked(self._by_ip_path)
                by_type = self._load_index_unlocked(self._by_type_path)
        except LockTimeout:
            log.warning(
                "index lock timeout — find() returns [] (ip=%r type=%r)",
                ip,
                type,
            )
            return []

        if ip is None and type is None:
            return []

        if ip is not None and type is not None:
            left = set(by_ip.get(ip) or [])
            ids = [i for i in (by_type.get(type) or []) if i in left]
        elif ip is not None:
            ids = list(by_ip.get(ip) or [])
        else:
            ids = list(by_type.get(type or "") or [])

        ids.reverse()
        return ids[:limit]

    def stats(self) -> IncidentStats:
        try:
            with meta_lock(self.meta_dir):
                raw = self._load_stats_unlocked()
        except LockTimeout:
            log.warning("index lock timeout — stats() returns empty snapshot")
            return IncidentStats(
                timezone=self.timezone,
                total=0,
                by_type={},
                by_hour=_empty_hours(),
                top_ips=[],
                updated_at="",
            )
        return IncidentStats(
            timezone=str(raw.get("timezone") or self.timezone),
            total=int(raw.get("total") or 0),
            by_type=dict(raw.get("by_type") or {}),
            by_hour={**_empty_hours(), **(raw.get("by_hour") or {})},
            top_ips=list(raw.get("top_ips") or []),
            updated_at=str(raw.get("updated_at") or ""),
        )

    def stats_dict(self) -> dict[str, Any]:
        """API/직렬화용 — 내부 ``_ip_counts`` 는 제외."""
        return asdict(self.stats())

    def _record_unlocked(
        self,
        *,
        incident_id: str,
        attack_type: str,
        client_ip: str | None,
        occurred_at: datetime | None,
    ) -> None:
        stats = self._load_stats_unlocked()
        by_ip = self._load_index_unlocked(self._by_ip_path)
        by_type = self._load_index_unlocked(self._by_type_path)

        hour = self._hour_key(occurred_at)
        stats["total"] = int(stats.get("total", 0)) + 1
        stats["timezone"] = self.timezone

        by_type_counts: dict[str, int] = dict(stats.get("by_type") or {})
        by_type_counts[attack_type] = by_type_counts.get(attack_type, 0) + 1
        stats["by_type"] = by_type_counts

        by_hour: dict[str, int] = {**_empty_hours(), **(stats.get("by_hour") or {})}
        by_hour[hour] = int(by_hour.get(hour, 0)) + 1
        stats["by_hour"] = by_hour

        ip_counts: dict[str, int] = dict(stats.get("_ip_counts") or {})
        if client_ip:
            ip_counts[client_ip] = ip_counts.get(client_ip, 0) + 1
            ids = list(by_ip.get(client_ip) or [])
            ids.append(incident_id)
            by_ip[client_ip] = ids[-self.max_ids_per_key :]
        stats["_ip_counts"] = ip_counts
        stats["top_ips"] = self._compute_top_ips(ip_counts)

        type_ids = list(by_type.get(attack_type) or [])
        type_ids.append(incident_id)
        by_type[attack_type] = type_ids[-self.max_ids_per_key :]

        stats["updated_at"] = datetime.now(ZoneInfo(self.timezone)).isoformat()

        atomic_write_json(self._stats_path, stats)
        atomic_write_json(self._by_ip_path, by_ip)
        atomic_write_json(self._by_type_path, by_type)

    def _hour_key(self, occurred_at: datetime | None) -> str:
        """시간대 키 (서비스 TZ 기준 hour).

        백엔드 계약 (실측: ``backend/.../IrForwarder.java``):
          LocalDateTime.format(ISO_LOCAL_DATE_TIME) → naive ISO 문자열.
          → 서비스 TZ(기본 Asia/Seoul)로 간주 (risk analyzer ``_time_weight`` 와 동일).

        aware 입력은 계약 외지만 방어적으로 ``astimezone`` 처리.
        occurred_at is None → 지금 발생으로 간주 ``now(tz)`` (관측 편의).
          (risk 는 판정 근거 부족으로 0점 — 용도가 달라 None 처리가 다름)
        """
        try:
            tz = ZoneInfo(self.timezone)
        except Exception:
            log.warning("invalid timezone=%r, fallback Asia/Seoul", self.timezone)
            tz = ZoneInfo("Asia/Seoul")

        if occurred_at is None:
            # 관측 편의: 지금 발생으로 간주 (risk 의 None→0 과 다름)
            local = datetime.now(tz)
        elif occurred_at.tzinfo is None:
            local = occurred_at.replace(tzinfo=tz)
        else:
            local = occurred_at.astimezone(tz)
        return f"{local.hour:02d}"

    def _compute_top_ips(self, ip_counts: dict[str, int]) -> list[dict[str, Any]]:
        ranked = sorted(ip_counts.items(), key=lambda kv: (-kv[1], kv[0]))
        return [{"ip": ip, "count": n} for ip, n in ranked[: self.top_ips_n]]

    def _load_stats_unlocked(self) -> dict[str, Any]:
        if not self._stats_path.exists():
            return {
                "timezone": self.timezone,
                "total": 0,
                "by_type": {},
                "by_hour": _empty_hours(),
                "top_ips": [],
                "_ip_counts": {},
                "updated_at": "",
            }
        try:
            return json.loads(self._stats_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {
                "timezone": self.timezone,
                "total": 0,
                "by_type": {},
                "by_hour": _empty_hours(),
                "top_ips": [],
                "_ip_counts": {},
                "updated_at": "",
            }

    @staticmethod
    def _load_index_unlocked(path: Path) -> dict[str, list[str]]:
        if not path.exists():
            return {}
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
        out: dict[str, list[str]] = {}
        for k, v in raw.items():
            if isinstance(v, list):
                out[str(k)] = [str(x) for x in v]
        return out
