"""
CYBERDUDEBIVASH® SENTINEL APEX — Structured Logging Module
JSON-structured logging for observability and audit trails.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


class StructuredFormatter(logging.Formatter):
    """Emit log records as JSON lines for machine parsing."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        extra_keys = {
            k: v
            for k, v in record.__dict__.items()
            if k not in logging.LogRecord.__dict__ and not k.startswith("_")
            and k not in ("message", "args", "msg", "exc_info", "exc_text",
                          "stack_info", "levelno", "levelname", "name",
                          "module", "funcName", "lineno", "pathname",
                          "filename", "created", "msecs", "relativeCreated",
                          "thread", "threadName", "processName", "process")
        }
        if extra_keys:
            payload["context"] = extra_keys
        return json.dumps(payload, default=str)


def setup_logger(name: str, logs_dir: str = "logs", level: int = logging.INFO) -> logging.Logger:
    """Configure and return a structured logger writing to stdout and a daily log file."""
    Path(logs_dir).mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger

    # Stdout handler
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(StructuredFormatter())
    logger.addHandler(sh)

    # Daily rotating file handler
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    fh = logging.FileHandler(os.path.join(logs_dir, f"syndication-{today}.log"))
    fh.setFormatter(StructuredFormatter())
    logger.addHandler(fh)

    return logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
