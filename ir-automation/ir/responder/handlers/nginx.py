"""nginx 핸들러 — deny 룰 파일을 활성 차단 목록으로 재생성하고 reload 한다.

선언적: deny.conf 를 매번 active 집합으로 통째로 다시 쓴다 → 만료 IP 는 파일에서
사라지고 reload 시 자동 해제. 파일 내용이 바뀔 때만 reload 해서 불필요한 신호를 줄인다.

전제: nginx 설정의 server/location 블록에 `include <deny_file>;` 가 걸려 있어야 한다.
운영주의: lab 은 단일 nginx IP 뒤에 있으므로, 차단 대상 IP 는 반드시
`X-Forwarded-For` 끝(실 클라이언트)에서 뽑힌 값이어야 전체차단을 피한다(앱과 동일 규약).
"""
from __future__ import annotations

import logging
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

from ir.responder.blocklist import BlockEntry
from ir.responder.handlers.base import BlockHandler

log = logging.getLogger("ir.responder.nginx")


class NginxHandler(BlockHandler):
    name = "nginx"

    def __init__(self, deny_file: Path, reload_cmd: str):
        self.deny_file = Path(deny_file)
        self.reload_cmd = reload_cmd

    def _render(self, active: list[BlockEntry]) -> str:
        lines = ["# AIR IR 자동 생성 — 직접 수정 금지"]
        for e in sorted(active, key=lambda x: x.ip):
            lines.append(f"deny {e.ip};  # {e.reason} exp={int(e.expires_at)}")
        return "\n".join(lines) + "\n"

    def apply(self, active: list[BlockEntry]) -> None:
        content = self._render(active)
        prev = self.deny_file.read_text(encoding="utf-8") if self.deny_file.exists() else None
        if content == prev:
            return  # 변경 없음 → reload 생략

        self.deny_file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.deny_file.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(tmp, self.deny_file)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

        self._reload()
        log.info("[NGINX] deny 룰 갱신 — 활성 %d건, reload 완료", len(active))

    def _reload(self) -> None:
        try:
            subprocess.run(shlex.split(self.reload_cmd), check=True,
                           capture_output=True, timeout=10)
        except (subprocess.SubprocessError, OSError) as e:
            # reload 실패해도 파일은 갱신됨 — 다음 reload/재기동 시 반영. 파이프라인은 계속.
            log.warning("[NGINX] reload 실패(파일은 갱신됨): %s", e)
