import json
import logging
import logging.config
import logging.handlers
import queue
import re
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Optional

from app.backend.config import settings

_correlation_id: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)

_SENSITIVE_PATTERNS = [
    (re.compile(r'(["\']?(?:api[_-]?key|apikey|secret|token|password|auth[ _-]?key|jwt[_-]?secret)["\']?)\s*[:=]\s*["\']?([^"\'&\s,}]+)', re.IGNORECASE), r'\1=****'),
    (re.compile(r'(Authorization|X-API-Key|Auth-Key|Bearer)\s*:\s*(\w+\s+)?\S+', re.IGNORECASE), r'\1: ****'),
    (re.compile(r'https?://[^:]+:[^@]+@'), 'https://****:****@'),
]


def _redact_text(value: str) -> str:
    for pattern, replacement in _SENSITIVE_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


class SensitiveDataFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pattern, replacement in _SENSITIVE_PATTERNS:
                record.msg = pattern.sub(replacement, record.msg)
        if record.args:
            cleaned = []
            for arg in record.args:
                if isinstance(arg, str):
                    for pattern, replacement in _SENSITIVE_PATTERNS:
                        arg = pattern.sub(replacement, arg)
                cleaned.append(arg)
            record.args = tuple(cleaned)
        return True


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()
        correlation_id = getattr(record, "correlation_id", None) or _correlation_id.get()
        entry = {
            "timestamp": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": _redact_text(record.getMessage()),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if correlation_id:
            entry["correlation_id"] = correlation_id
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = _redact_text(self.formatException(record.exc_info))
        return json.dumps(entry, default=str)


class CorrelationIDFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "correlation_id", None):
            return True
        correlation_id = _correlation_id.get()
        record.correlation_id = correlation_id or ""
        return True


_configured: bool = False
_log_queue: Optional[queue.Queue] = None
_queue_listener: Optional[logging.handlers.QueueListener] = None


def _install_queue_listener() -> None:
    """Route all log records through an async-friendly queue.

    WU-0.6: sync I/O (JSON formatting + stdout writes) is moved off the event
    loop onto a dedicated listener thread, so a slow/blocked console never
    stalls request handling.
    """
    global _log_queue, _queue_listener
    if _queue_listener is not None:
        _queue_listener.stop()
        _queue_listener = None

    target = None
    for name in list(logging.Logger.manager.loggerDict):
        logger = logging.Logger.manager.loggerDict.get(name)
        if isinstance(logger, logging.Logger):
            for handler in logger.handlers:
                if isinstance(handler, logging.StreamHandler):
                    target = handler
                    break
            if target is not None:
                break

    if target is None:
        return

    _log_queue = queue.Queue(maxsize=-1)
    queue_handler = logging.handlers.QueueHandler(_log_queue)
    queue_handler.setLevel(logging.NOTSET)
    queue_handler.addFilter(CorrelationIDFilter())

    _queue_listener = logging.handlers.QueueListener(_log_queue, target, respect_handler_level=True)
    _queue_listener.start()

    for name in list(logging.Logger.manager.loggerDict):
        logger = logging.Logger.manager.loggerDict.get(name)
        if not isinstance(logger, logging.Logger):
            continue
        logger.handlers = [
            queue_handler if isinstance(h, logging.StreamHandler) else h
            for h in logger.handlers
        ]


def configure_logging():
    global _configured
    log_level_str = settings.log_level.upper()

    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {
            "sensitive_data": {
                "()": SensitiveDataFilter,
            },
            "correlation_id": {
                "()": CorrelationIDFilter,
            },
        },
        "formatters": {
            "json": {
                "()": JSONFormatter,
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": log_level_str,
                "formatter": "json",
                "stream": "ext://sys.stdout",
                "filters": ["sensitive_data", "correlation_id"],
            },
        },
        "loggers": {
            "ioc-platform": {
                "level": log_level_str,
                "handlers": ["console"],
                "propagate": False,
            },
            "uvicorn": {
                "level": "WARNING",
                "handlers": ["console"],
                "propagate": False,
            },
            "uvicorn.access": {
                "level": "WARNING",
                "handlers": ["console"],
                "propagate": False,
            },
            "uvicorn.error": {
                "level": "WARNING",
                "handlers": ["console"],
                "propagate": False,
            },
            "sqlalchemy.engine.Engine": {
                "level": "WARNING",
                "propagate": True,
            },
            "sqlalchemy": {
                "level": "WARNING",
                "propagate": False,
            },
            "sqlalchemy.pool": {
                "level": "WARNING",
                "propagate": True,
            },
            "sqlalchemy.dialects": {
                "level": "WARNING",
                "propagate": True,
            },
            "sqlalchemy.orm": {
                "level": "WARNING",
                "propagate": True,
            },
        },
    }
    logging.config.dictConfig(config)
    _install_queue_listener()
    _configured = True


_null_handler = logging.NullHandler()
_ioc_logger = logging.getLogger("ioc-platform")
_ioc_logger.addHandler(_null_handler)
_ioc_logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"ioc-platform.{name}")


def describe_exception(exc: BaseException, limit: int = 300) -> str:
    """Return a never-empty, redacted, bounded description of an exception.

    Many network exceptions (``httpx.ConnectError()``, ``asyncio.TimeoutError()``,
    ``ReadTimeout('')``) have an empty ``str()``, which previously produced log
    lines such as ``"Provider failed: "``.  This always includes the exception
    type, falls back to ``repr`` when the message is empty, and appends the
    direct cause/context type (httpx wraps the underlying socket error).
    """
    message = str(exc).strip()
    text = f"{type(exc).__name__}: {message}" if message else f"{type(exc).__name__} ({exc!r})"
    cause = exc.__cause__ or exc.__context__
    if cause is not None and cause is not exc:
        cause_message = str(cause).strip()
        text += f" <- {type(cause).__name__}" + (f": {cause_message}" if cause_message else "")
    text = _redact_text(text)
    if len(text) > limit:
        text = text[: max(0, limit - 3)] + "..."
    return text


__all__ = ["get_logger", "_correlation_id", "configure_logging", "describe_exception"]
