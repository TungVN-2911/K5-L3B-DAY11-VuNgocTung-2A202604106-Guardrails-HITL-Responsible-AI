"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        key = request_id or f"{user_id}:{len(self.logs)}"
        self._open[key] = time.monotonic()
        self.logs.append({
            "request_id": key,
            "user_id": user_id,
            "input": text,
            "timestamp": utc_now_iso(),
            "blocked": False,
            "layer": None,
        })

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        if request_id:
            key = request_id
        else:
            open_keys = [
                open_key for open_key in reversed(list(self._open))
                if open_key.startswith(f"{user_id}:")
            ]
            key = open_keys[0] if open_keys else f"{user_id}:default"
        started = self._open.pop(key, None)
        latency_ms = (
            (time.monotonic() - started) * 1000.0
            if started is not None
            else 0.0
        )

        entry = next(
            (item for item in reversed(self.logs) if item["request_id"] == key),
            None,
        )
        if entry is None:
            entry = {
                "request_id": key,
                "user_id": user_id,
                "input": "",
                "timestamp": utc_now_iso(),
            }
            self.logs.append(entry)

        entry.update({
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": round(latency_ms, 3),
        })

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
