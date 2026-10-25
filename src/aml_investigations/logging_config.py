"""Structured JSON logging with request/case correlation IDs.

One JSON object per line on stdout. Every record carries the service
name; records emitted while serving a request carry ``request_id``,
and records emitted while working a case carry ``case_id`` — set via
context variables by the API middleware and the services.
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from datetime import datetime, timezone

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id", default=None
)
case_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "case_id", default=None
)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": "aml-investigations",
        }
        request_id = request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        case_id = getattr(record, "case_id", None) or case_id_var.get()
        if case_id:
            payload["case_id"] = case_id
        for key in ("event", "actor", "status", "alert_id"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    # uvicorn's own loggers would double-print; route them through root.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers = []
        logger.propagate = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
