"""Structured JSON logging for operational logs.

Separate from the append-only audit log (which records every request). This is
the operational trace: scan starts/finishes, recon runs, scheduler ticks.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in ("program", "target", "module", "count", "duration_s"):
            val = getattr(record, key, None)
            if val is not None:
                entry[key] = val
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry)


def get_logger(name: str, *, level: int = logging.INFO) -> logging.Logger:
    """Return a JSON-formatted logger named `name`."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
    return logger


def log_event(logger: logging.Logger, msg: str, **attrs):
    """Emit a structured log with extra attrs."""
    logger.info(msg, extra=attrs)
