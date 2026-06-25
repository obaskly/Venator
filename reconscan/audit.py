"""Append-only audit log. Every outbound request is recorded as one JSON line."""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from typing import Optional


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        # touch the file so it exists even on a zero-request run
        with open(self.path, "a", encoding="utf-8"):
            pass

    def record(self, method: str, url: str, *, phase: str = "",
               status: Optional[int] = None, note: str = "",
               tool: str = "reconscan") -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "epoch": round(time.time(), 3),
            "method": method,
            "url": url,
            "status": status,
            "phase": phase,
            "tool": tool,
            "note": note,
        }
        line = json.dumps(entry, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def count(self) -> int:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                return sum(1 for _ in fh)
        except FileNotFoundError:
            return 0
