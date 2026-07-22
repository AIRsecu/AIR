"""원자적 JSON 쓰기 + 선택적 flock (POSIX only).

Windows 등 fcntl 미지원 환경에서는 락을 skip 하고 single-writer 전제로 동작한다.
락 파일은 메타 디렉터리의 단일 ``.lock`` 을 쓰며, 호출측이 ``lock_dir`` 을 넘긴다.

획득: LOCK_EX|LOCK_NB + 재시도. timeout 초과 시 ``LockTimeout``.
"""
from __future__ import annotations

import errno
import json
import logging
import os
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

log = logging.getLogger("ir.store.atomic")

try:
    import fcntl
    _HAS_FLOCK = True
except ImportError:  # Windows 등 non-POSIX
    fcntl = None  # type: ignore[assignment]
    _HAS_FLOCK = False

_warned_no_flock: bool = False

# meta_lock 타임아웃 (초) — 무한 대기(stall) 방지
_LOCK_TIMEOUT_SECONDS = 2.0
_LOCK_RETRY_INTERVAL = 0.05


class LockTimeout(Exception):
    """incident_meta/.lock 획득 실패 (timeout)."""


def _warn_no_flock_once() -> None:
    global _warned_no_flock
    if not _HAS_FLOCK and not _warned_no_flock:
        log.warning(
            "fcntl 미지원 환경 — 파일 락 비활성화 (single-writer 전제)"
        )
        _warned_no_flock = True


def _is_lock_busy(exc: BaseException) -> bool:
    if isinstance(exc, BlockingIOError):
        return True
    if isinstance(exc, OSError):
        return exc.errno in (
            errno.EAGAIN,
            errno.EWOULDBLOCK,
            getattr(errno, "EACCES", -1),
        )
    return False


@contextmanager
def meta_lock(
    lock_dir: Path,
    *,
    timeout: float | None = None,
    retry_interval: float | None = None,
) -> Iterator[None]:
    """incident_meta/.lock 단일 락으로 메타 읽기/쓰기 직렬화.

    - flock 미지원: 경고 1회 후 no-op (single-writer 전제)
    - flock 지원: LOCK_EX|LOCK_NB 재시도, timeout 초과 시 LockTimeout
    """
    _warn_no_flock_once()
    lock_dir = Path(lock_dir)
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / ".lock"
    timeout = _LOCK_TIMEOUT_SECONDS if timeout is None else timeout
    retry_interval = _LOCK_RETRY_INTERVAL if retry_interval is None else retry_interval

    if not _HAS_FLOCK:
        yield
        return

    assert fcntl is not None
    lock_path.touch(exist_ok=True)
    lf = open(lock_path, "a+", encoding="utf-8")
    acquired = False
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(lf.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except Exception as e:
                if not _is_lock_busy(e):
                    raise
                if time.monotonic() >= deadline:
                    raise LockTimeout(
                        f"meta_lock timeout after {timeout}s: {lock_path}"
                    ) from e
                time.sleep(retry_interval)
        try:
            yield
        finally:
            if acquired:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    finally:
        lf.close()


def atomic_write_json(path: Path, data: dict) -> None:
    """tempfile.mkstemp + os.replace. 락은 호출측 ``meta_lock`` 에서 잡는다."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
