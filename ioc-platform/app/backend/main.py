import asyncio
import hmac
import ipaddress
import json
import os
import re
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlsplit
from uuid import uuid4

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import AliasChoices, BaseModel, model_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from datetime import datetime
from app.backend.adapters.base import CompositeScore, EnrichmentData, LookupResponse
from app.backend.batch import (
    _persist_batch,
    consolidate_batch_results,
    delete_batch_from_db,
    discard_batch,
    get_all_batches_from_db,
    get_batch,
    get_batch_from_db,
    _normalize_batch_payload,
    acquire_batch_queue,
    release_batch_queue,
    parse_csv,
    parse_json,
    shutdown_batch_tasks,
    start_batch_analysis,
)
from app.backend.cache import CacheLayer
from app.backend.circuit_breaker import all_breaker_states
from app.backend.classifier import SUPPORTED_IOC_TYPES, classify_ioc, is_password_digest, normalize_ioc, parse_typed_ioc, password_digest, refang
from app.backend.misp_export import build_misp_event
from app.backend.siem_export import export_siem
from app.backend.http_client import close_client as close_http_client, get_client as _get_http_client
from app.backend.config import settings
from app.backend.thresholds import DISPLAY_MALICIOUS, DISPLAY_SUSPICIOUS
from app.backend.database import cleanup_old_lookups, get_db, init_db, persisted_verdict_fields, retry_sqlite_commit, upsert_lookup_result
from app.backend.models import IOC, Investigation, InvestigationIOC, LookupResult, IOCFeedback
from app.backend.pipeline import ADAPTERS, AnalysisTask, TERMINAL_TASK_STATES, cancel_analysis, cleanup_old_tasks, get_cache, get_rate_limiter, get_task_queue, get_task_redis, mark_task_cancelled, register_pending_task, register_running_task, release_running_task, run_analysis, set_cache, set_rate_limiter, cleanup_task_queue, task_response_payload
from app.backend.schemas import (
    BatchStatusResponse,
    CacheClearResponse,
    ErrorResponse,
    HealthResponse,
    InvestigationCreateResponse,
    InvestigationDetail,
    InvestigationSummary,
    IOCInInvestigation,
    RecentIOCResponse,
    SaveResponse,
    StatusResponse,
    TaskStatusResponse,
    WebhookResponse,
    FeedbackRequest,
    FeedbackResponse,
)
from app.backend.rate_limiter import RateLimiter
from app.backend.stix_export import build_stix_bundle, results_to_csv
from app.backend.webhooks import add_webhook, list_webhooks, remove_webhook, shutdown_webhook_tasks
from app.backend.logger import configure_logging, describe_exception, get_logger, _correlation_id

logger = get_logger("main")

_lookup_tasks: set[asyncio.Task] = set()
_lookup_semaphore: asyncio.Semaphore | None = None
_lookup_semaphore_loop: asyncio.AbstractEventLoop | None = None
_pending_lookups = 0
# (ioc_type, value, fp_override) -> task_id of the lookup currently queued or
# running for that indicator.  A repeated submission (double Enter, re-search
# while the first is running) joins that task instead of spending provider
# quota on an identical second fan-out.  Refresh requests never coalesce.
_inflight_lookups: dict[tuple[str, str, bool], str] = {}


def _get_lookup_semaphore() -> asyncio.Semaphore:
    global _lookup_semaphore, _lookup_semaphore_loop, _pending_lookups
    loop = asyncio.get_running_loop()
    if _lookup_semaphore is None or _lookup_semaphore_loop is not loop:
        _lookup_semaphore = asyncio.Semaphore(max(1, settings.max_concurrent_lookups))
        _lookup_semaphore_loop = loop
        _pending_lookups = 0
    return _lookup_semaphore


async def _run_queued_lookup(*args, **kwargs) -> None:
    global _pending_lookups
    task_id = kwargs.get("task_id")
    started = False
    try:
        async with _get_lookup_semaphore():
            started = True
            await run_analysis(*args, **kwargs)
    except asyncio.CancelledError:
        if task_id and not started:
            # Cancelled while still queued: run_analysis never ran, so give
            # the registered pending task its terminal state here.
            await mark_task_cancelled(task_id)
        raise
    except Exception as exc:
        # run_analysis records its own failures; this only fires for errors
        # outside it, which would otherwise leave the task pending forever.
        logger.error("Queued lookup %s failed: %s", task_id, describe_exception(exc), exc_info=exc)
        if task_id:
            from app.backend.pipeline import get_task

            task = get_task(task_id)
            if task is not None and task.status not in TERMINAL_TASK_STATES:
                task.status = "error"
                task.error = describe_exception(exc, limit=200)
                task.progress = 100.0
    finally:
        _pending_lookups = max(0, _pending_lookups - 1)


def _lookup_task_done(task: asyncio.Task) -> None:
    _lookup_tasks.discard(task)
    task_id = getattr(task, "_ioc_task_id", None)
    if task_id:
        release_running_task(task_id, task)
    for key, inflight_id in list(_inflight_lookups.items()):
        if inflight_id == task_id:
            _inflight_lookups.pop(key, None)
    if not task.cancelled():
        task.exception()


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    _setup_exception_hooks()
    await init_db()

    _cache = CacheLayer(redis_url=settings.redis_url or None)
    await _cache._get_redis()
    set_cache(_cache)

    _rate_limiter = RateLimiter(redis_url=settings.redis_url or None)
    set_rate_limiter(_rate_limiter)

    # Adapters are bound to the shared HTTP client at import time; a previous
    # lifespan (tests, reload) may have closed it, so re-bind a live client.
    http_client = _get_http_client()
    for adapter in ADAPTERS:
        adapter.set_client(http_client)

    cleanup_task = asyncio.create_task(_periodic_cleanup())
    from app.backend.enrichment import start_cisa_background_refresh, stop_cisa_background_refresh
    await start_cisa_background_refresh()
    try:
        yield
    except asyncio.CancelledError:
        pass
    finally:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        await stop_cisa_background_refresh()
        lookup_tasks = list(_lookup_tasks)
        for task in lookup_tasks:
            task.cancel()
        if lookup_tasks:
            await asyncio.gather(*lookup_tasks, return_exceptions=True)
        _lookup_tasks.clear()
        await shutdown_batch_tasks()
        await shutdown_webhook_tasks()
        _inflight_lookups.clear()
        await _cache.close()
        await _rate_limiter.close()
        await close_http_client()
        set_cache(None)
        set_rate_limiter(None)
        from app.backend.database import engine as _db_engine

        await _db_engine.dispose()


def _global_exception_handler(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger.critical("Unhandled exception", exc_info=(exc_type, exc_value, exc_traceback))


def _setup_exception_hooks():
    sys.excepthook = _global_exception_handler
    asyncio.get_event_loop().set_exception_handler(_async_exception_handler)


def _async_exception_handler(loop, context):
    exc = context.get("exception")
    msg = context.get("message", "Unhandled async exception")
    if exc:
        logger.error("Async exception: %s", msg, exc_info=exc)
    else:
        logger.error("Async exception: %s", msg)


async def _periodic_cleanup():
    while True:
        try:
            await asyncio.sleep(1800)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Periodic cleanup sleep failed")
            continue
        try:
            await cleanup_old_tasks()
        except Exception:
            logger.exception("Task cleanup failed")
        try:
            await cleanup_old_lookups()
        except Exception:
            logger.exception("Lookup retention cleanup failed")


app = FastAPI(
    title="Universal IOC Lookup Platform",
    version="0.2.0",
    lifespan=lifespan,
    docs_url="/docs" if not settings.api_keys else None,
    redoc_url="/redoc" if not settings.api_keys else None,
    openapi_url="/openapi.json" if not settings.api_keys else None,
)


def _configured_origins() -> tuple[str, ...]:
    return tuple(
        origin.rstrip("/")
        for origin in (item.strip() for item in settings.cors_origins.split(","))
        if origin and origin != "*"
    )


def _configured_trusted_hosts() -> tuple[str, ...]:
    hosts = ["localhost", "127.0.0.1", "::1"]
    for origin in _configured_origins():
        parsed = urlparse(origin if "://" in origin else f"//{origin}")
        if parsed.hostname:
            hosts.append(parsed.hostname)
    for host in (item.strip() for item in settings.trusted_hosts.split(",")):
        if host:
            hosts.append(host)
    if settings.base_url:
        parsed = urlparse(settings.base_url)
        if parsed.hostname:
            hosts.append(parsed.hostname)
    return tuple(dict.fromkeys(hosts))


CORS_ORIGINS = _configured_origins()
TRUSTED_HOSTS = _configured_trusted_hosts()


def _route_template(request: Request) -> str:
    route = request.scope.get("route")
    return getattr(route, "path", None) or "unmatched"


def _safe_correlation_id(value: str | None) -> str:
    if value and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        return value
    return str(uuid4())


def _client_class(request: Request) -> str:
    host = request.client.host if request.client else None
    if not host:
        return "unknown"
    return "loopback" if _is_loopback_client(host) else "remote"


class RequestBoundaryMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") not in CORS_ORIGINS:
            request.state.request_guard = "origin_rejected"
            logger.warning("Rejected request with disallowed origin")
            return Response(
                status_code=403,
                content="Request origin is not allowed",
                media_type="text/plain",
            )
        request.state.request_guard = "allowed"
        return await call_next(request)


class RequestAuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        correlation_id = _safe_correlation_id(request.headers.get("X-Correlation-ID"))
        request.state.correlation_id = correlation_id
        token = _correlation_id.set(correlation_id)
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            logger.info(
                "HTTP request method=%s route=%s status=%s client=%s auth=%s guard=%s",
                request.method,
                _route_template(request),
                status_code,
                _client_class(request),
                getattr(request.state, "auth_result", "unknown"),
                getattr(request.state, "request_guard", "unknown"),
            )
            _correlation_id.reset(token)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' "
            "https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; connect-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'"
        )
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cid = _safe_correlation_id(
            request.headers.get("X-Correlation-ID")
            or getattr(request.state, "correlation_id", None)
        )
        _correlation_id.set(cid)
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = cid
        return response


PUBLIC_API_PATHS = {"/api/health"}


def _is_loopback_client(host: str | None) -> bool:
    if not host:
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return host.lower() == "localhost"


def _trusted_proxy(request: Request) -> bool:
    if not settings.trust_proxy or not request.client:
        return False
    client_host = request.client.host
    allowed = {item.strip() for item in settings.trusted_proxy_hosts.split(",") if item.strip()}
    return client_host in allowed


def _request_is_https(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    if not _trusted_proxy(request):
        return False
    forwarded = request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
    return forwarded == "https"


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_host = request.client.host if request.client else None
        if not settings.allow_network_bind and not _is_loopback_client(client_host):
            request.state.auth_result = "network_blocked"
            return Response(
                status_code=403,
                content="Network access is disabled for this local instance",
                media_type="text/plain",
            )
        if settings.allow_network_bind and settings.require_network_tls and not _request_is_https(request):
            request.state.auth_result = "tls_required"
            return Response(
                status_code=400,
                content="HTTPS is required for network access",
                media_type="text/plain",
            )
        path = request.url.path
        if not path.startswith("/api/") or path in PUBLIC_API_PATHS:
            request.state.auth_result = "public"
            return await call_next(request)

        api_keys = settings.api_keys
        valid_keys = [key.strip() for key in api_keys.split(",") if key.strip()]
        if settings.allow_network_bind and (
            not valid_keys or any(len(key) < 16 for key in valid_keys)
        ):
            request.state.auth_result = "misconfigured"
            logger.error("Authentication is not configured for network binding")
            return Response(
                status_code=503,
                content="Authentication is not configured",
                media_type="text/plain",
            )
        if api_keys and not valid_keys:
            request.state.auth_result = "misconfigured"
            logger.error("Authentication is misconfigured: API_KEYS contains no usable keys")
            return Response(
                status_code=503,
                content="Authentication is not configured",
                media_type="text/plain",
            )

        if valid_keys:
            provided = request.headers.get("X-API-Key", "")
            if not any(hmac.compare_digest(provided, valid_key) for valid_key in valid_keys):
                request.state.auth_result = "failed"
                logger.warning(
                    "Authentication failed route=%s client=%s",
                    _route_template(request),
                    _client_class(request),
                )
                return Response(
                    status_code=401,
                    content="Invalid or missing API key",
                    headers={"WWW-Authenticate": "ApiKey"},
                    media_type="text/plain",
                )
            request.state.auth_result = "authenticated"
        else:
            request.state.auth_result = "not_configured"
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    RATE_LIMITS: dict[str, tuple[int, int]] = {
        "/api/lookup": (30, 60),
        "/api/batch": (10, 60),
        "/api/enrich": (30, 60),
    }
    GLOBAL_LIMITS: dict[str, tuple[int, int]] = {
        "/api/lookup": (300, 60),
        "/api/batch": (100, 60),
    }

    async def dispatch(self, request: Request, call_next):
        for prefix, (limit, window) in self.RATE_LIMITS.items():
            if request.url.path.startswith(prefix):
                # Status polling of batches (GET) should not be throttled to 10/min
                if prefix == "/api/batch" and request.method == "GET":
                    continue
                if prefix == "/api/tasks" and request.method == "GET":
                    continue
                # Reading stored results (/api/lookup/stored, /api/lookup/{ioc}/raw)
                # starts no provider work and must not consume the submission quota.
                if prefix == "/api/lookup" and request.method == "GET":
                    continue

                client_ip = request.client.host if request.client else "unknown"
                if _trusted_proxy(request):
                    xff = request.headers.get("X-Forwarded-For")
                    if xff:
                        client_ip = xff.split(",")[0].strip()
                    else:
                        x_real_ip = request.headers.get("X-Real-IP")
                        if x_real_ip:
                            client_ip = x_real_ip.strip()

                limiter = get_rate_limiter()
                if limiter is not None:
                    try:
                        # Global rate limit check
                        if prefix in self.GLOBAL_LIMITS:
                            glimit, gwindow = self.GLOBAL_LIMITS[prefix]
                            effective_glimit = settings.lookup_global_rate_limit_per_minute if prefix == "/api/lookup" else glimit
                            global_allowed = await limiter.acquire(f"global:{prefix}:{request.method}", effective_glimit, gwindow)
                            if not global_allowed:
                                return Response(
                                    status_code=429,
                                    content="Rate limit exceeded: Global rate limit. Try again later.",
                                    headers={"Retry-After": "60"},
                                    media_type="text/plain",
                                )

                        effective_limit = settings.lookup_rate_limit_per_minute if prefix == "/api/lookup" else limit
                        effective_window = settings.lookup_rate_window if prefix == "/api/lookup" else window
                        allowed = await limiter.acquire(f"ip:{client_ip}", effective_limit, effective_window)
                        if not allowed:
                            return Response(
                                status_code=429,
                                content="Rate limit exceeded. Try again later.",
                                headers={"Retry-After": "60"},
                                media_type="text/plain",
                            )
                    except Exception:
                        logger.exception("Rate limiter failure")
                        return Response(
                            status_code=503,
                            content="Rate limiter unavailable",
                            media_type="text/plain",
                        )
                break
        return await call_next(request)


app.add_middleware(AuthMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(CORS_ORIGINS),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Correlation-ID"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(TRUSTED_HOSTS))
app.add_middleware(RequestBoundaryMiddleware)
app.add_middleware(RequestAuditMiddleware)


# --- Exception Handlers ---

def _error_response(detail: str, error_code: str | None = None) -> ErrorResponse:
    return ErrorResponse(
        detail=detail,
        error_code=error_code,
        request_id=_correlation_id.get(),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    safe_errors = [
        {"loc": [str(part) for part in error.get("loc", ())], "type": error.get("type", ""), "msg": error.get("msg", "")}
        for error in errors
    ]
    logger.warning("Validation error route=%s errors=%s", _route_template(request), safe_errors)
    detail = "; ".join(f"{'.'.join(str(p) for p in e.get('loc', []))}: {e.get('msg', '')}" for e in errors)
    return JSONResponse(
        status_code=422,
        content=_error_response(detail, error_code="validation_error").model_dump(),
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_response(exc.detail).model_dump(),
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.critical("Unhandled exception route=%s", _route_template(request), exc_info=exc)
    return JSONResponse(
        status_code=500,
        content=_error_response("Internal server error", error_code="internal_error").model_dump(),
    )


class LookupRequest(BaseModel):
    ioc: str
    task_id: str | None = None
    ioc_type: str | None = None
    refresh: bool = False

    @model_validator(mode="before")
    @classmethod
    def accept_legacy_input(cls, value):
        if isinstance(value, dict) and "ioc" not in value and "input" in value:
            return {**value, "ioc": value["input"]}
        return value


class InvestigationCreate(BaseModel):
    name: str
    description: str = ""


class InvestigationUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class NoteUpdate(BaseModel):
    notes: str = ""


# --- Health ---

@app.get("/api/adapters/health", response_model=dict)
async def adapter_health():
    return {"adapters": all_breaker_states()}


_ADAPTER_CREDENTIAL_FIELDS = {
    "MalwareBazaar": "malwarebazaar_api_key",
    "ThreatFox": "threatfox_api_key",
    "URLhaus": "urlhaus_api_key",
    "VirusTotal": "virustotal_api_key",
    "AbuseIPDB": "abuseipdb_api_key",
    "urlscan.io": "urlscanio_api_key",
    "Tria.ge": "triage_api_key",
    "Hybrid Analysis": "hybridanalysis_api_key",
    "GreyNoise": "greynoise_api_key",
    "AlienVault OTX": "alienvault_otx_api_key",
    "Shodan": "shodan_api_key",
    "Censys": "censys_api_key",
    "IPinfo": "ipinfo_api_key",
    "AbstractAPI": "abstractapi_email_api_key",
    "AbstractAPI IP": "abstractapi_ip_api_key",
    "AbstractAPI Phone": "abstractapi_phone_api_key",
    "IPQualityScore Phone": "ipquality_api_key",
    "IPQualityScore IP": "ipquality_api_key",
    "IPQualityScore Email": "ipquality_api_key",
    "Hunter.io": "hunterio_api_key",
    "NVD": "nvd_api_key",
    "Etherscan": "etherscan_api_key",
    "ChainAbuse": "chainabuse_api_key",
    "FileScan.io": "filescan_api_key",
    "Hudson Rock": "hudson_api_key",
}


@app.get("/api/sources", response_model=dict)
async def source_inventory():
    """Safe source inventory: reports configuration state, never credentials."""
    from app.backend.adapters.base import is_valid_api_key

    sources = []
    for adapter in ADAPTERS:
        key = getattr(adapter, "api_key", None)
        requires_key = key is not None and not getattr(adapter, "public_without_key", False)
        enabled_by_policy = settings.is_source_enabled(adapter.name)
        field_name = _ADAPTER_CREDENTIAL_FIELDS.get(adapter.name)
        env_name, origin = settings.credential_origin(field_name) if field_name else (None, None)
        if env_name is None and field_name:
            alias = type(settings).model_fields[field_name].validation_alias
            env_name = alias.choices[0] if isinstance(alias, AliasChoices) else str(alias)
        configured = is_valid_api_key(key) if key is not None else True
        if configured and key:
            credential_source = ".env" if origin == ".env" else "environment"
        elif not requires_key or getattr(adapter, "public_without_key", False):
            credential_source = "public_no_key"
        else:
            credential_source = "not_configured"
        sources.append({
            "name": adapter.name,
            "supported_types": list(adapter.supported_types),
            "public_without_key": bool(getattr(adapter, "public_without_key", False)),
            "requires_key": requires_key,
            "configured": configured,
            "available": enabled_by_policy and (configured or bool(getattr(adapter, "public_without_key", False)) or key is None),
            "enabled_by_policy": enabled_by_policy,
            "credential_env": env_name,
            "credential_source": credential_source,
            "rate_limit_per_minute": adapter.rate_limit.requests_per_minute,
        })
    return {
        "sources": sources,
        "count": len(sources),
        "available_count": sum(1 for s in sources if s["available"]),
        "credential_configured_count": sum(1 for s in sources if s["credential_source"] in {".env", "environment"}),
    }


@app.get("/api/health/keys", response_model=dict)
async def key_health():
    inv = await source_inventory()
    sources = inv.get("sources", [])
    keys: dict[str, bool] = {}
    missing_keys: list[str] = []
    public_providers: list[str] = []
    for s in sources:
        name = s["name"]
        configured = bool(s["configured"])
        keys[name] = configured
        if s["credential_source"] == "public_no_key":
            public_providers.append(name)
        elif not configured:
            missing_keys.append(name)
    return {
        "keys": keys,
        "active_providers": inv.get("available_count", 0),
        "total_providers": inv.get("count", 0),
        "missing_keys": missing_keys,
        "public_providers": public_providers,
    }


@app.get("/api/health", response_model=HealthResponse)
async def health():
    return HealthResponse(status="ok", app="Universal IOC Lookup Platform", version="0.2.0")


@app.post("/api/cache/clear", response_model=CacheClearResponse)
async def clear_cache():
    c = get_cache()
    if c is not None:
        await c.clear()
    return CacheClearResponse(status="ok")


def _parse_stored_response(payload: dict, fallback_task_id: str | None = None) -> LookupResponse:
    if not isinstance(payload, dict):
        raise ValueError("Stored result must be an object")
    if "input" not in payload or "composite" not in payload:
        from app.backend.pipeline import AnalysisTask

        task = AnalysisTask.from_dict(payload)
        data = {
            "input": task.ioc_value,
            "task_id": task.task_id or fallback_task_id,
            "normalized": task.normalized or task.ioc_value,
            "ioc_type": task.ioc_type or "unknown",
            "password_prehashed": task.password_prehashed,
            "composite": task.composite or CompositeScore(),
            "final_assessment": task.final_assessment,
            "provider_health": task.provider_health,
            "enrichment": task.enrichment or EnrichmentData(),
            "results": task.results,
            "relationships": task.relationships,
            "executive_summary": task.executive_summary,
        }
    else:
        data = dict(payload)
        data.setdefault("task_id", fallback_task_id)
        data.setdefault("normalized", data.get("input", ""))
        data.setdefault("ioc_type", "unknown")
        data.setdefault("composite", CompositeScore())
        data.setdefault("provider_health", [])
        data.setdefault("enrichment", EnrichmentData())
        data.setdefault("results", [])
        data.setdefault("relationships", [])
        data.setdefault("executive_summary", "")
    return LookupResponse.model_validate(data)


def _task_from_stored_response(response: LookupResponse) -> "AnalysisTask":
    from app.backend.pipeline import AnalysisTask

    return AnalysisTask(
        task_id=response.task_id or "",
        status="done",
        progress=100.0,
        ioc_value=response.input,
        normalized=response.normalized,
        ioc_type=response.ioc_type,
        password_prehashed=response.password_prehashed,
        results=response.results,
        composite=response.composite,
        final_assessment=response.final_assessment,
        provider_health=response.provider_health,
        enrichment=response.enrichment,
        relationships=response.relationships,
        executive_summary=response.executive_summary,
    )


async def _load_stored_response(task_id: str, db: AsyncSession) -> LookupResponse | None:
    result = await db.execute(
        select(LookupResult)
        .where(LookupResult.task_id == task_id)
        .order_by(LookupResult.created_at.desc(), LookupResult.id.desc())
        .limit(1)
    )
    row = result.scalar_one_or_none()
    if row is None or not row.full_response:
        return None
    try:
        return _parse_stored_response(json.loads(row.full_response), task_id)
    except (TypeError, ValueError, KeyError) as exc:
        logger.warning("Ignoring malformed stored result for task %s: %s", task_id, exc)
        return None


# --- Pipeline Lookup ---

async def _resolve_task(ioc: str, task_id: str | None = None, db: AsyncSession | None = None):
    if not task_id:
        raise HTTPException(status_code=400, detail="task_id is required for export")
    task = await get_task_redis(task_id)
    if task is None and db is not None:
        response = await _load_stored_response(task_id, db)
        if response is not None:
            task = _task_from_stored_response(response)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status != "done":
        raise HTTPException(status_code=425, detail="Analysis not yet complete")
    requested_ioc = refang(ioc.strip()).lower()
    task_ioc = refang(task.normalized or task.ioc_value or "").lower()
    if task_ioc and task_ioc != requested_ioc:
        raise HTTPException(status_code=409, detail="Task does not belong to this IOC")
    return task


async def _fetch_fp_overrides(db: AsyncSession) -> set[str]:
    if settings.allow_network_bind and not settings.allow_global_feedback:
        return set()
    rows = (
        await db.execute(select(IOCFeedback.ioc_value).where(IOCFeedback.feedback == "false_positive"))
    ).scalars().all()
    return set(rows)


def _normalize_ioc(value: str) -> str:
    normalized = refang(value.strip())
    if not normalized:
        raise HTTPException(status_code=400, detail="Empty IOC value")
    if len(normalized) > 2048:
        raise HTTPException(status_code=400, detail="IOC value too long")
    parsed = urlsplit(normalized.strip("`'\"<>()[],;"))
    if parsed.scheme.lower() in {"http", "https"} and (parsed.username is not None or parsed.password is not None):
        raise HTTPException(status_code=400, detail="URL userinfo is not allowed")
    return normalized


def _reject_ambiguous_ingress(value: str, requested_type: str | None, normalized_info) -> None:
    parsed_type, _ = parse_typed_ioc(refang(value.strip()))
    if requested_type or parsed_type:
        return
    if normalized_info.ioc_type in {"service_name", "mutex", "named_pipe", "registry_key"}:
        raise HTTPException(status_code=400, detail="Host-artifact values must use an explicit type prefix")


def _feedback_value(value: str, requested_type: str | None = None) -> str:
    normalized = _normalize_ioc(value)
    parsed_type, parsed_value = parse_typed_ioc(normalized)
    if parsed_type is not None and requested_type is None:
        normalized = parsed_value
    normalized_info = normalize_ioc(normalized, expected_type=requested_type or parsed_type)
    if not normalized_info.valid:
        raise HTTPException(status_code=400, detail="Unrecognizable IOC format")
    _reject_ambiguous_ingress(value, requested_type, normalized_info)
    normalized = normalized_info.value
    if normalized_info.ioc_type == "password":
        if requested_type == "password_sha1" or parsed_type == "password_sha1" or (
            requested_type in {None, "password"} and is_password_digest(normalized)
        ):
            return normalized.lower()
        return password_digest(normalized)
    return normalized


def _task_to_response(task) -> LookupResponse:
    return LookupResponse(
        input=task.ioc_value,
        task_id=task.task_id,
        normalized=task.normalized,
        ioc_type=task.ioc_type or "unknown",
        password_prehashed=task.password_prehashed or (
            task.ioc_type == "password" and bool(re.fullmatch(r"[a-f0-9]{40}", task.normalized or "", re.IGNORECASE))
        ),
        composite=task.composite or CompositeScore(),
        final_assessment=getattr(task, "final_assessment", None),
        provider_health=getattr(task, "provider_health", []),
        enrichment=task.enrichment or EnrichmentData(),
        results=task.results,
        relationships=task.relationships,
        executive_summary=task.executive_summary,
    )


@app.post("/api/lookup", response_model=TaskStatusResponse)
async def start_lookup(request: LookupRequest, db: AsyncSession = Depends(get_db)):
    req_type = request.ioc_type
    normalized = _normalize_ioc(request.ioc)
    parsed_type, parsed_value = parse_typed_ioc(normalized)
    if parsed_type is not None and req_type is None:
        req_type = parsed_type
        normalized = parsed_value
    prehashed_password = req_type == "password_sha1" or (
        req_type == "password" and is_password_digest(normalized)
    )
    normalized_info = normalize_ioc(normalized, expected_type=req_type)
    if not normalized_info.valid:
        raise HTTPException(status_code=400, detail="Unrecognizable IOC format")
    _reject_ambiguous_ingress(request.ioc, request.ioc_type, normalized_info)
    normalized = normalized_info.value
    effective_type = "password" if prehashed_password else (req_type or normalized_info.ioc_type)
    if effective_type not in SUPPORTED_IOC_TYPES:
        raise HTTPException(status_code=400, detail="Unsupported IOC type")

    fp_override = normalized in await _fetch_fp_overrides(db)

    target_ioc = normalized
    if effective_type == "password":
        target_ioc = password_digest(normalized, already_digest=prehashed_password)

    global _pending_lookups
    _get_lookup_semaphore()
    inflight_key = (effective_type, target_ioc, bool(fp_override))
    if not request.refresh:
        existing_id = _inflight_lookups.get(inflight_key)
        existing = await get_task_redis(existing_id) if existing_id else None
        if existing is not None and existing.status not in TERMINAL_TASK_STATES:
            return TaskStatusResponse(
                task_id=existing.task_id,
                status=existing.status,
                progress=existing.progress,
                stages=existing.to_dict()["stages"],
                ioc_value=target_ioc,
                normalized=target_ioc,
                ioc_type=effective_type,
            )
    if _pending_lookups >= settings.max_pending_lookups:
        raise HTTPException(status_code=429, detail="Lookup queue is full; retry later")
    _pending_lookups += 1
    task_id = uuid4().hex[:12]
    analysis_kwargs = {
        "task_id": task_id,
        "fp_override": fp_override,
        "ioc_type_override": effective_type,
        "password_prehashed": effective_type == "password",
    }
    if request.refresh:
        analysis_kwargs["bypass_cache"] = True
    pending_task = register_pending_task(
        task_id, target_ioc, effective_type, password_prehashed=effective_type == "password",
    )
    try:
        task = asyncio.create_task(_run_queued_lookup(target_ioc, **analysis_kwargs))
    except Exception:
        _pending_lookups = max(0, _pending_lookups - 1)
        raise
    task._ioc_task_id = task_id  # type: ignore[attr-defined]
    register_running_task(task_id, task)
    _inflight_lookups[inflight_key] = task_id
    _lookup_tasks.add(task)
    task.add_done_callback(_lookup_task_done)
    return TaskStatusResponse(
        task_id=task_id,
        status="pending",
        stages=pending_task.to_dict()["stages"],
        ioc_value=target_ioc,
        normalized=target_ioc,
        ioc_type=effective_type,
    )


@app.get("/api/tasks/{task_id}")
async def get_task_status(task_id: str, db: AsyncSession = Depends(get_db)):
    task = await get_task_redis(task_id)
    if task:
        return task.to_dict()
    response = await _load_stored_response(task_id, db)
    if response:
        return _task_from_stored_response(response).to_dict()
    raise HTTPException(status_code=404, detail="Task not found")


@app.post("/api/tasks/{task_id}/cancel")
async def cancel_task(task_id: str):
    task = await get_task_redis(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status in {"done", "error", "cancelled"}:
        raise HTTPException(status_code=409, detail="Analysis is already complete")
    if not cancel_analysis(task_id):
        raise HTTPException(status_code=409, detail="Analysis is not cancellable")
    return {"task_id": task_id, "status": "cancelling"}


SSE_HEARTBEAT_INTERVAL = 15.0
SSE_IDLE_TIMEOUT = 300.0
SSE_QUEUE_TIMEOUT = 2.0


@app.get("/api/tasks/{task_id}/stream")
async def stream_task(task_id: str, request: Request):
    # Subscribe before reading the task state so a task that finishes in
    # between still delivers its "done" event to this queue.
    queue = get_task_queue(task_id)
    task = await get_task_redis(task_id)
    if task is None:
        cleanup_task_queue(task_id)
        raise HTTPException(status_code=404, detail="Task not found")

    async def event_generator():
        last_heartbeat = asyncio.get_running_loop().time()
        last_event = asyncio.get_running_loop().time()
        try:
            if task.status in TERMINAL_TASK_STATES:
                # Already finished: report it instead of idling until timeout.
                payload = {"status": task.status, "progress": task.progress, "error": task.error}
                yield f"event: done\ndata: {json.dumps(payload)}\n\n"
                return
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event, data = await asyncio.wait_for(queue.get(), timeout=SSE_QUEUE_TIMEOUT)
                    yield f"event: {event}\ndata: {json.dumps(data)}\n\n"
                    last_event = asyncio.get_running_loop().time()
                    if event == "done":
                        break
                except asyncio.TimeoutError:
                    now = asyncio.get_running_loop().time()
                    if now - last_event >= SSE_IDLE_TIMEOUT:
                        break
                    if now - last_heartbeat >= SSE_HEARTBEAT_INTERVAL:
                        last_heartbeat = now
                        yield "event: heartbeat\ndata: {}\n\n"
                    else:
                        yield ": keepalive\n\n"
        finally:
            cleanup_task_queue(task_id)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/tasks/{task_id}/result")
async def get_task_result(task_id: str, db: AsyncSession = Depends(get_db)):
    task = await get_task_redis(task_id)
    if task:
        if task.status == "error":
            raise HTTPException(status_code=409, detail=f"Analysis failed: {task.error or 'unknown error'}")
        if task.status == "cancelled":
            raise HTTPException(status_code=409, detail="Analysis was cancelled")
        if task.status != "done":
            raise HTTPException(status_code=425, detail="Analysis not yet complete")
        return _task_to_response(task)
    response = await _load_stored_response(task_id, db)
    if response:
        return response
    raise HTTPException(status_code=404, detail="Task not found")


# --- Investigations ---

@app.get("/api/investigations", response_model=list[InvestigationSummary])
async def list_investigations(db: AsyncSession = Depends(get_db)):
    stmt = select(Investigation).order_by(Investigation.updated_at.desc())
    result = await db.execute(stmt)
    invs = result.scalars().all()
    return [
        InvestigationSummary(
            id=inv.id,
            name=inv.name,
            description=inv.description or "",
            ioc_count=len(inv.iocs) if inv.iocs else 0,
            created_at=inv.created_at.isoformat() if inv.created_at else None,
            updated_at=inv.updated_at.isoformat() if inv.updated_at else None,
        )
        for inv in invs
    ]


@app.post("/api/investigations", response_model=InvestigationCreateResponse)
async def create_investigation(body: InvestigationCreate, db: AsyncSession = Depends(get_db)):
    inv = Investigation(name=body.name, description=body.description)
    db.add(inv)
    await retry_sqlite_commit(db)
    await db.refresh(inv)
    return InvestigationCreateResponse(
        id=inv.id,
        name=inv.name,
        description=inv.description,
        created_at=inv.created_at.isoformat() if inv.created_at else None,
    )


@app.get("/api/investigations/{inv_id}", response_model=InvestigationDetail)
async def get_investigation(inv_id: int, db: AsyncSession = Depends(get_db)):
    stmt = (
        select(Investigation)
        .options(
            selectinload(Investigation.iocs).selectinload(InvestigationIOC.ioc),
        )
        .where(Investigation.id == inv_id)
    )
    inv = (await db.execute(stmt)).scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    ioc_ids = [ii.ioc_id for ii in inv.iocs if ii.ioc_id is not None]

    latest_by_ioc: dict[int, LookupResult] = {}
    if ioc_ids:
        rows = (
            await db.execute(
                select(LookupResult)
                .where(LookupResult.ioc_id.in_(ioc_ids))
                .order_by(LookupResult.ioc_id, LookupResult.created_at.desc())
            )
        ).scalars().all()
        for lr in rows:
            latest_by_ioc.setdefault(lr.ioc_id, lr)

    iocs_data = []
    for ii in inv.iocs:
        ioc = ii.ioc
        latest = latest_by_ioc.get(ioc.id)
        iocs_data.append(IOCInInvestigation(
            id=ii.id,
            ioc_id=ioc.id,
            value=ioc.value,
            ioc_type=ioc.ioc_type,
            notes=ii.notes or "",
            score=latest.composite_score if latest else None,
            verdict=latest.composite_verdict if latest else None,
            looked_up_at=latest.created_at.isoformat() if latest and latest.created_at else None,
        ))

    return InvestigationDetail(
        id=inv.id,
        name=inv.name,
        description=inv.description or "",
        iocs=iocs_data,
        created_at=inv.created_at.isoformat() if inv.created_at else None,
        updated_at=inv.updated_at.isoformat() if inv.updated_at else None,
    )


@app.put("/api/investigations/{inv_id}", response_model=StatusResponse)
async def update_investigation(inv_id: int, body: InvestigationUpdate, db: AsyncSession = Depends(get_db)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if body.name is not None:
        inv.name = body.name
    if body.description is not None:
        inv.description = body.description
    await retry_sqlite_commit(db)
    return StatusResponse(status="updated")


@app.delete("/api/investigations/{inv_id}", response_model=StatusResponse)
async def delete_investigation(inv_id: int, db: AsyncSession = Depends(get_db)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    await db.delete(inv)
    await retry_sqlite_commit(db)
    return StatusResponse(status="deleted")


@app.post("/api/investigations/{inv_id}/iocs")
async def add_ioc_to_investigation(inv_id: int, body: LookupRequest, db: AsyncSession = Depends(get_db)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    normalized = _normalize_ioc(body.ioc)
    parsed_type, parsed_value = parse_typed_ioc(normalized)
    if parsed_type is not None and body.ioc_type is None:
        normalized = parsed_value
    input_type = body.ioc_type or parsed_type
    normalized_info = normalize_ioc(normalized, expected_type=input_type)
    if not normalized_info.valid:
        raise HTTPException(status_code=400, detail="Unrecognizable IOC format")
    _reject_ambiguous_ingress(body.ioc, body.ioc_type, normalized_info)
    normalized = normalized_info.value
    prehashed_password = input_type == "password_sha1" or (
        input_type == "password" and is_password_digest(normalized)
    )
    ioc_type = "password" if prehashed_password else (input_type or normalized_info.ioc_type)
    if ioc_type == "password" or classify_ioc(normalized) == "password":
        normalized = password_digest(normalized, already_digest=prehashed_password)
        ioc_type = "password"

    existing = await db.execute(select(IOC).where(IOC.value == normalized))
    ioc = existing.scalar_one_or_none()
    if not ioc:
        ioc = IOC(value=normalized, ioc_type=ioc_type)
        db.add(ioc)
        await db.flush()
    ioc_id = ioc.id

    already = await db.execute(
        select(InvestigationIOC).where(
            InvestigationIOC.investigation_id == inv_id,
            InvestigationIOC.ioc_id == ioc_id,
        )
    )
    if not already.scalar_one_or_none():
        ii = InvestigationIOC(investigation_id=inv_id, ioc_id=ioc_id)
        db.add(ii)

    await retry_sqlite_commit(db)

    await _auto_score_ioc(normalized, ioc_id, db, ioc_type)
    return {"status": "added", "ioc_id": ioc_id, "value": normalized}


@app.put("/api/investigations/{inv_id}/iocs/{ii_id}", response_model=StatusResponse)
async def update_ioc_notes(inv_id: int, ii_id: int, body: NoteUpdate, db: AsyncSession = Depends(get_db)):
    ii = await db.get(InvestigationIOC, ii_id)
    if not ii or ii.investigation_id != inv_id:
        raise HTTPException(status_code=404, detail="Not found")
    ii.notes = body.notes
    await retry_sqlite_commit(db)
    return StatusResponse(status="updated")


@app.delete("/api/investigations/{inv_id}/iocs/{ii_id}", response_model=StatusResponse)
async def remove_ioc_from_investigation(inv_id: int, ii_id: int, db: AsyncSession = Depends(get_db)):
    ii = await db.get(InvestigationIOC, ii_id)
    if not ii or ii.investigation_id != inv_id:
        raise HTTPException(status_code=404, detail="Not found")
    await db.delete(ii)
    await retry_sqlite_commit(db)
    return StatusResponse(status="removed")


# --- Recent Lookups ---

@app.get("/api/recent", response_model=list[RecentIOCResponse])
async def recent_lookups(db: AsyncSession = Depends(get_db)):
    # History is ordered by the most recent lookup of each indicator, so a
    # re-scanned IOC moves to the top, and reports that lookup's verdict and
    # time.  Only summary columns are read: loading every stored full_response
    # (the IOC.lookup_results relationship) just to pick the newest was heavy.
    #
    # Batch rows are excluded.  ``_persist_batch`` writes every completed
    # subtask to LookupResult tagged with its batch_id so a batch survives a
    # restart, which meant a 100-IOC batch injected 100 entries into the
    # single-scan history.  Those IOCs belong to the batch, and they are still
    # reachable through /api/batches and /api/batch/{id}/result.  The filter is
    # applied INSIDE the latest-per-IOC subquery as well, so an IOC whose most
    # recent result happened to come from a batch still reports its latest
    # genuine single-scan verdict rather than being dropped.
    latest_id = (
        select(LookupResult.ioc_id, func.max(LookupResult.id).label("latest_id"))
        .where(LookupResult.batch_id.is_(None))
        .group_by(LookupResult.ioc_id)
        .subquery()
    )
    stmt = (
        select(
            IOC.id,
            IOC.value,
            IOC.ioc_type,
            IOC.created_at,
            LookupResult.composite_verdict,
            LookupResult.composite_score,
            LookupResult.composite_confidence,
            LookupResult.created_at,
        )
        .outerjoin(latest_id, latest_id.c.ioc_id == IOC.id)
        .outerjoin(LookupResult, LookupResult.id == latest_id.c.latest_id)
        .where(
            # An IOC known only through a batch must not appear here at all.
            LookupResult.id.isnot(None)
        )
        .order_by(
            func.coalesce(LookupResult.created_at, IOC.created_at).desc(),
            func.coalesce(LookupResult.id, 0).desc(),
            IOC.id.desc(),
        )
        .limit(50)
    )
    rows = (await db.execute(stmt)).all()
    out = []
    for ioc_id, value, ioc_type, ioc_created, verdict, score, confidence, scanned_at in rows:
        timestamp = scanned_at or ioc_created
        out.append(RecentIOCResponse(
            id=ioc_id,
            value=value,
            ioc_type=ioc_type,
            verdict=verdict,
            score=score,
            confidence=confidence,
            created_at=timestamp.isoformat() if timestamp else None,
        ))
    return out


@app.delete("/api/recent/{ioc_id}", response_model=StatusResponse)
async def delete_recent(ioc_id: int, db: AsyncSession = Depends(get_db)):
    ioc = await db.get(IOC, ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="Not found")
    await db.delete(ioc)
    await retry_sqlite_commit(db)
    return StatusResponse(status="deleted")


@app.get("/api/recent/{ioc_id}/result")
async def get_recent_result(ioc_id: int, db: AsyncSession = Depends(get_db)):
    """Return the previously stored LookupResponse from database without re-running any provider scan."""
    stmt = (
        select(LookupResult)
        .where(LookupResult.ioc_id == ioc_id)
        .order_by(LookupResult.created_at.desc(), LookupResult.id.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    lr = result.scalar_one_or_none()
    if not lr or not lr.full_response:
        raise HTTPException(status_code=404, detail="No stored result found for this IOC")
    try:
        return _parse_stored_response(json.loads(lr.full_response), lr.task_id).model_dump(mode="json")
    except Exception as exc:
        logger.error("Failed to parse stored LookupResult for ioc_id %s: %s", ioc_id, type(exc).__name__)
        raise HTTPException(status_code=500, detail="Corrupted stored result")


def _stored_ioc_value(value: str) -> str:
    """The IOC.value a completed lookup of ``value`` is stored under.

    Lookups persist the classifier-normalized value (lower-cased domain,
    canonical URL, password digest), so a raw refang is not enough to find
    them again.  Falls back to the refanged input for unrecognized values.
    """
    refanged = _normalize_ioc(value)
    try:
        return _feedback_value(value)
    except HTTPException:
        return refanged


@app.get("/api/lookup/stored")
async def get_stored_lookup(ioc: str, db: AsyncSession = Depends(get_db)):
    """Fetch previously stored result by IOC value if already analyzed, preserving API key quotas."""
    normalized = _stored_ioc_value(ioc)
    stmt = (
        select(LookupResult)
        .join(IOC, IOC.id == LookupResult.ioc_id)
        .where(IOC.value == normalized)
        .order_by(LookupResult.created_at.desc(), LookupResult.id.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    lr = result.scalar_one_or_none()
    if not lr or not lr.full_response:
        raise HTTPException(status_code=404, detail="No stored result found for this indicator")
    try:
        return _parse_stored_response(json.loads(lr.full_response), lr.task_id).model_dump(mode="json")
    except Exception as exc:
        logger.error("Failed to parse stored LookupResult: %s", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Corrupted stored result")



@app.get("/api/lookup/{ioc}/raw")
async def get_raw_lookup(ioc: str, db: AsyncSession = Depends(get_db)):
    normalized = _stored_ioc_value(ioc)
    result = await db.execute(
        select(LookupResult)
        .join(IOC, IOC.id == LookupResult.ioc_id)
        .where(IOC.value == normalized)
        .order_by(LookupResult.created_at.desc(), LookupResult.id.desc())
        .limit(1)
    )
    row = result.scalar_one_or_none()
    if row is None or not row.full_response:
        raise HTTPException(status_code=404, detail="No stored result found for this indicator")
    try:
        response = _parse_stored_response(json.loads(row.full_response), row.task_id).model_dump(mode="json")
    except Exception as exc:
        logger.exception("Failed to parse stored raw result: %s", exc)
        raise HTTPException(status_code=500, detail="Corrupted stored result")
    providers = []
    for provider in response.get("results", []):
        providers.append({
            "source": provider.get("source", "unknown"),
            "execution_state": provider.get("execution_state", "unknown"),
            "verdict": provider.get("verdict", "unknown"),
            "provider_verdict": provider.get("provider_verdict"),
            "provider_summary": provider.get("provider_summary"),
            "raw_data": provider.get("raw_data", {}),
        })
    return {
        "ioc": normalized,
        "ioc_type": response.get("ioc_type", "unknown"),
        "provider_count": len(providers),
        "providers": providers,
    }


# --- False-Positive Feedback (A-2) ---

def _require_feedback_scope():
    if settings.allow_network_bind and not settings.allow_global_feedback:
        raise HTTPException(status_code=403, detail="Global feedback is disabled in network mode")


@app.post("/api/feedback", response_model=FeedbackResponse)
async def submit_feedback(body: FeedbackRequest, db: AsyncSession = Depends(get_db)):
    value = _feedback_value(body.ioc, body.ioc_type)
    if body.feedback not in ("false_positive", "confirmed"):
        raise HTTPException(status_code=400, detail="feedback must be 'false_positive' or 'confirmed'")
    _require_feedback_scope()

    existing = (
        await db.execute(select(IOCFeedback).where(IOCFeedback.ioc_value == value))
    ).scalar_one_or_none()
    if existing:
        existing.feedback = body.feedback
        existing.note = body.note
    else:
        existing = IOCFeedback(ioc_value=value, feedback=body.feedback, note=body.note)
        db.add(existing)
    await retry_sqlite_commit(db)
    await db.refresh(existing)
    return FeedbackResponse(
        ioc_value=existing.ioc_value,
        feedback=existing.feedback,
        note=existing.note,
        created_at=existing.created_at.isoformat() if existing.created_at else None,
    )


@app.get("/api/feedback/{ioc}", response_model=FeedbackResponse)
async def get_feedback(ioc: str, db: AsyncSession = Depends(get_db)):
    _require_feedback_scope()
    value = _feedback_value(ioc)
    row = (
        await db.execute(select(IOCFeedback).where(IOCFeedback.ioc_value == value))
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="No feedback recorded for this IOC")
    return FeedbackResponse(
        ioc_value=row.ioc_value,
        feedback=row.feedback,
        note=row.note,
        created_at=row.created_at.isoformat() if row.created_at else None,
    )


@app.delete("/api/feedback/{ioc}", response_model=StatusResponse)
async def delete_feedback(ioc: str, db: AsyncSession = Depends(get_db)):
    _require_feedback_scope()
    value = _feedback_value(ioc)
    row = (
        await db.execute(select(IOCFeedback).where(IOCFeedback.ioc_value == value))
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="No feedback recorded for this IOC")
    await db.delete(row)
    await retry_sqlite_commit(db)
    return StatusResponse(status="deleted")


# --- Batch Analysis ---

class BatchRequest(BaseModel):
    iocs: list[str]
    timeout: Optional[float] = None
    concurrency: Optional[int] = None


@app.post("/api/batch", response_model=BatchStatusResponse)
async def start_batch(body: BatchRequest, db: AsyncSession = Depends(get_db)):
    if not body.iocs:
        raise HTTPException(status_code=400, detail="No IOCs provided")
    if len(body.iocs) > settings.max_batch_iocs:
        raise HTTPException(status_code=400, detail=f"Maximum {settings.max_batch_iocs} IOCs per batch")

    fp_overrides = await _fetch_fp_overrides(db)
    try:
        batch = start_batch_analysis(body.iocs, fp_overrides=fp_overrides,
                                     timeout=body.timeout, concurrency=body.concurrency)
        await _persist_batch(batch, required=True)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return BatchStatusResponse(batch_id=batch.batch_id, total=batch.total, status=batch.status)


MAX_UPLOAD_SIZE = 10 * 1024 * 1024


@app.post("/api/batch/upload", response_model=BatchStatusResponse)
async def upload_batch_file(file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    try:
        raw = b""
        chunk_size = 0
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            chunk_size += len(chunk)
            if chunk_size > MAX_UPLOAD_SIZE:
                raise HTTPException(status_code=400, detail="File too large (max 10MB)")
            raw += chunk
        content = raw.decode("utf-8")
        filename = file.filename or "iocs.csv"
        if filename.endswith(".json"):
            iocs = parse_json(content)
        else:
            iocs = parse_csv(content)

        if not iocs:
            raise HTTPException(status_code=400, detail="No IOCs found in file")
        if len(iocs) > settings.max_batch_iocs:
            raise HTTPException(status_code=400, detail=f"Maximum {settings.max_batch_iocs} IOCs per batch")

        fp_overrides = await _fetch_fp_overrides(db)
        batch = start_batch_analysis(iocs, fp_overrides=fp_overrides)
        await _persist_batch(batch, required=True)
        return BatchStatusResponse(batch_id=batch.batch_id, total=batch.total, status=batch.status)
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("File upload failed")
        raise HTTPException(status_code=400, detail="Failed to parse file")


@app.get("/api/batch/{batch_id}")
async def get_batch_status(batch_id: str):
    batch = get_batch(batch_id)
    if batch:
        return batch.to_dict()
    persisted = await get_batch_from_db(batch_id)
    if persisted:
        return persisted
    raise HTTPException(status_code=404, detail="Batch not found")


@app.get("/api/batch/{batch_id}/result")
async def get_batch_result(batch_id: str):
    batch = get_batch(batch_id)
    if batch:
        if batch.status not in {"done", "cancelled", "error"}:
            raise HTTPException(status_code=425, detail="Batch analysis not yet complete")
        result = _normalize_batch_payload(
            consolidate_batch_results(batch),
            batch_id=batch.batch_id,
            status=batch.status,
            total=batch.total,
            completed=batch.completed,
            error=batch.error,
        )
        return result
    db_result = await get_batch_from_db(batch_id)
    if db_result:
        if db_result.get("status") not in {"done", "completed", "cancelled", "error"}:
            raise HTTPException(status_code=425, detail="Batch analysis not yet complete")
        return db_result
    raise HTTPException(status_code=404, detail="Batch not found")


@app.get("/api/batches")
async def list_batches():
    """Return lightweight summaries of all historical batches from SQLite."""
    return await get_all_batches_from_db()


@app.post("/api/batch/{batch_id}/cancel")
async def cancel_batch(batch_id: str):
    batch = get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    if batch.status == "cancelled":
        return {"batch_id": batch_id, "status": "cancelled"}
    if batch.status in {"done", "error"}:
        raise HTTPException(status_code=409, detail="Batch is already complete")
    batch.cancel_event.set()
    if batch.run_task is not None and not batch.run_task.done():
        batch.run_task.cancel()
        await asyncio.gather(batch.run_task, return_exceptions=True)
    if batch.status not in {"cancelled", "done", "error"}:
        batch.status = "cancelled"
        batch.error = "Batch cancelled"
        batch.progress = 100.0
        await _persist_batch(batch, required=True)
    return {"batch_id": batch_id, "status": batch.status}


@app.delete("/api/batch/{batch_id}")
async def delete_batch(batch_id: str):
    """Delete a batch from the SQLite database."""
    batch = get_batch(batch_id)
    if batch and batch.status in {"pending", "running"}:
        batch.cancel_event.set()
        if batch.run_task is not None and not batch.run_task.done():
            batch.run_task.cancel()
            await asyncio.gather(batch.run_task, return_exceptions=True)
    deleted = await delete_batch_from_db(batch_id)
    if not deleted and batch is None:
        raise HTTPException(status_code=404, detail="Batch not found in database")
    discard_batch(batch_id)
    return {"status": "deleted", "batch_id": batch_id, "database_record": deleted}


@app.get("/api/batch/{batch_id}/ioc/{ioc:path}")
async def get_batch_ioc_result(batch_id: str, ioc: str, db: AsyncSession = Depends(get_db)):
    """Retrieve full LookupResponse for a single IOC directly from completed batch results without re-scanning."""
    normalized = _normalize_ioc(ioc)
    batch = get_batch(batch_id)
    if batch:
        target_task = None
        for task in batch.subtasks:
            if task.normalized == normalized or task.ioc_value == normalized or task.ioc_value == ioc:
                target_task = task
                break
        if not target_task:
            raise HTTPException(status_code=404, detail="IOC not found in this batch")
        return _task_to_response(target_task)

    stored = await db.execute(
        select(LookupResult)
        .join(IOC, IOC.id == LookupResult.ioc_id)
        .where(LookupResult.batch_id == batch_id, IOC.value == normalized)
        .order_by(LookupResult.created_at.desc())
        .limit(1)
    )
    row = stored.scalar_one_or_none()
    if row and row.full_response:
        try:
            return _parse_stored_response(json.loads(row.full_response), row.task_id).model_dump(mode="json")
        except Exception as exc:
            logger.warning("Ignoring malformed batch result %s: %s", row.id, exc)

    db_result = await get_batch_from_db(batch_id)
    if db_result:
        for item in db_result.get("results", []):
            if item.get("normalized") == normalized or item.get("input") == normalized or item.get("input") == ioc or item.get("ioc") == normalized or item.get("ioc") == ioc:
                return item
        raise HTTPException(status_code=404, detail="IOC not found in this batch")

    raise HTTPException(status_code=404, detail="Batch not found")



@app.get("/api/batch/{batch_id}/stream")
async def stream_batch(batch_id: str, request: Request):
    batch = get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    queue = acquire_batch_queue(batch_id)

    async def event_generator():
        last_heartbeat = asyncio.get_running_loop().time()
        last_event = asyncio.get_running_loop().time()
        try:
            if batch.status in {"done", "cancelled", "error"}:
                # Finished before the client subscribed: report it and close
                # instead of idling until the SSE timeout.
                payload = {"batch_id": batch_id, "status": batch.status, "progress": 100.0, "error": batch.error}
                yield f"event: batch_done\ndata: {json.dumps(payload)}\n\n"
                return
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event, data = await asyncio.wait_for(queue.get(), timeout=SSE_QUEUE_TIMEOUT)
                    yield f"event: {event}\ndata: {json.dumps(data)}\n\n"
                    last_event = asyncio.get_running_loop().time()
                    if event in {"batch_done", "batch_error"}:
                        break
                except asyncio.TimeoutError:
                    now = asyncio.get_running_loop().time()
                    if now - last_event >= SSE_IDLE_TIMEOUT:
                        break
                    if now - last_heartbeat >= SSE_HEARTBEAT_INTERVAL:
                        last_heartbeat = now
                        yield "event: heartbeat\ndata: {}\n\n"
                    else:
                        yield ": keepalive\n\n"
        finally:
            release_batch_queue(batch_id)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# --- Export ---

class ReportExportRequest(BaseModel):
    ioc: str
    task_id: str | None = None

@app.post("/api/export/report")
async def export_report(body: ReportExportRequest, db: AsyncSession = Depends(get_db)):
    normalized = _normalize_ioc(body.ioc)
    task = await _resolve_task(body.ioc, body.task_id, db)
    response = _task_to_response(task).model_dump()

    html = _build_html_report(response)
    return HTMLResponse(html, media_type="text/html",
                        headers={"Content-Disposition": f'attachment; filename="ioc_report_{normalized}.html"'})

def _build_html_report(data: dict) -> str:
    ioc_val = data.get("normalized") or data.get("input") or "Unknown"
    ioc_type = data.get("ioc_type", "")
    comp = data.get("composite", {})
    assessment = data.get("final_assessment") or {}
    verdict = assessment.get("final_verdict", comp.get("verdict", "unknown"))
    score = assessment.get("normalized_score", comp.get("score"))
    score_str = f"{round(score)}/100" if score is not None else "—"
    confidence = assessment.get("confidence", comp.get("confidence", "medium"))
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    results = data.get("results", [])
    enrich = data.get("enrichment", {})
    summary = data.get("executive_summary", "")
    source_count = len(results)

    html = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root { --bg: #f5f6fa; --bg-card: #ffffff; --text: #1a1a2e; --muted: #718096; --border: #e2e8f0; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
  .container { max-width: 960px; margin: 0 auto; }
  h1 { font-size: 1.6rem; font-weight: 700; margin-bottom: 0.15rem; }
  .meta { color: var(--muted); font-size: 0.85rem; margin-bottom: 1.5rem; }
  .banner { display: flex; align-items: center; gap: 1rem; background: var(--bg-card); padding: 1rem 1.25rem; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-bottom: 1.5rem; }
  .badge { display: inline-block; padding: 0.2rem 0.7rem; border-radius: 20px; font-weight: 600; font-size: 0.78rem; text-transform: uppercase; letter-spacing: .04em; }
  .badge-malicious { background: #fed7d7; color: #c53030; }
  .badge-suspicious { background: #fefcbf; color: #975a16; }
  .badge-clean { background: #c6f6d5; color: #276749; }
  .badge-unknown { background: #e2e8f0; color: #4a5568; }
  .score-display { font-size: 1.8rem; font-weight: 800; }
  .score-red { color: #e53e3e; } .score-amber { color: #dd6b20; } .score-green { color: #38a169; }
  h2 { font-size: 1.1rem; font-weight: 600; margin: 1.5rem 0 0.75rem; padding-bottom: 0.3rem; border-bottom: 2px solid var(--border); color: #2d3748; }
  table { width: 100%; border-collapse: collapse; background: var(--bg-card); border-radius: 8px; overflow: hidden; box-shadow: 0 1px 2px rgba(0,0,0,.06); }
  th, td { text-align: left; padding: 0.5rem 0.75rem; font-size: 0.85rem; border-bottom: 1px solid var(--border); }
  th { background: #f7fafc; font-weight: 600; color: #4a5568; font-size: 0.78rem; text-transform: uppercase; letter-spacing: .04em; }
  tr:last-child td { border-bottom: none; }
  .mono { font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 0.82rem; }
  .tag { display: inline-block; background: #edf2f7; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.7rem; margin: 0.1rem; color: #4a5568; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin: 0.5rem 0; }
  .stat-card { background: var(--bg-card); padding: 0.75rem 1rem; border-radius: 8px; box-shadow: 0 1px 2px rgba(0,0,0,.06); }
  .stat-num { font-size: 1.4rem; font-weight: 700; } .stat-lbl { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
  .stat-sub { font-size: 0.82rem; color: #4a5568; margin-top: 0.2rem; }
  .footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); font-size: 0.75rem; color: var(--muted); text-align: center; }
</style>
</head>
<body><div class="container">"""

    html += f"""
<h1>Threat Intelligence Report</h1>
<p class="meta">IOC Universal — {_e(date_str)}</p>
<div class="banner">
  <div>
    <div style="font-size:0.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:0.15rem">{_e(ioc_type)}</div>
    <div class="mono" style="font-weight:600;font-size:1.05rem">{_e(ioc_val)}</div>
  </div>
  <div style="margin-left:auto;text-align:right">
    <div><span class="badge badge-{_e(verdict)}">{_e(verdict)}</span></div>
    <div class="score-display score-{"red" if (score or 0) >= DISPLAY_MALICIOUS else "amber" if (score or 0) >= DISPLAY_SUSPICIOUS else "green"}">{_e(score_str)}</div>
    <div style="font-size:0.72rem;color:var(--muted)">confidence: {_e(confidence)} &middot; {source_count} source(s)</div>
  </div>
</div>"""

    if summary:
        v_color = "#e53e3e" if verdict == "malicious" else "#dd6b20" if verdict == "suspicious" else "#38a169"
        html += f'<div style="background:var(--bg-card);padding:1rem 1.25rem;border-radius:8px;margin-bottom:1rem;border-left:4px solid {v_color}"><strong>Executive Summary:</strong><br>{_e(summary)}</div>'

    html += '<h2>Source Results</h2>'
    if results:
        html += '<table><thead><tr><th>Source</th><th>Verdict</th><th>Score</th><th>Tags</th></tr></thead><tbody>'
        for r in results:
            rs = r.get("raw_score")
            rs_str = f"{round(rs * 100)}/100" if rs is not None else "—"
            tags = " ".join(f'<span class="tag">{_e(t)}</span>' for t in (r.get("tags") or [])[:8])
            html += f'<tr><td class="mono">{_e(r.get("source",""))}</td>'
            html += f'<td><span class="badge badge-{_e(r.get("verdict","unknown"))}">{_e(r.get("verdict","unknown"))}</span></td>'
            html += f'<td>{_e(rs_str)}</td><td>{tags}</td></tr>'
        html += '</tbody></table>'
    else:
        html += '<p style="color:var(--muted)">No source results returned.</p>'

    html += '<h2>Enrichment</h2><div class="grid-2">'
    if enrich.get("geoip") and enrich["geoip"].get("country"):
        g = enrich["geoip"]
        html += f'<div class="stat-card"><div class="stat-num">{_e(g.get("country",""))}</div><div class="stat-lbl">Country{"; " + _e(g.get("city","")) if g.get("city") else ""}</div><div class="stat-sub">AS{_e(g.get("asn",""))} &middot; {_e(g.get("isp",""))}</div></div>'
    if enrich.get("whois") and enrich["whois"].get("registrar"):
        w = enrich["whois"]
        html += f'<div class="stat-card"><div class="stat-num">{_e(w.get("registrar",""))}</div><div class="stat-lbl">Registrar &middot; created {_e(w.get("creation_date","") or "?")}</div></div>'
    if enrich.get("ssl") and enrich["ssl"].get("subject"):
        s = enrich["ssl"]
        html += f'<div class="stat-card"><div class="stat-num">{_e(s.get("subject",""))}</div><div class="stat-lbl">SSL{" [EXPIRED]" if s.get("is_expired") else ""}</div><div class="stat-sub">issuer: {_e(s.get("issuer","") or "?")} &middot; days left: {_e(s.get("days_left","?"))}</div></div>'
    if enrich.get("passive_dns") and enrich["passive_dns"].get("records"):
        pdns = enrich["passive_dns"]["records"]
        html += f'<div class="stat-card"><div class="stat-num">{len(pdns)}</div><div class="stat-lbl">Passive DNS Records</div></div>'
    if enrich.get("open_ports") and enrich["open_ports"]:
        ports = enrich["open_ports"]
        html += f'<div class="stat-card"><div class="stat-num">{len(ports)}</div><div class="stat-lbl">Open Ports</div><div class="stat-sub">{", ".join(_e(str(p)) for p in ports[:10])}</div></div>'
    if enrich.get("dns") and enrich["dns"].get("a_records"):
        dns = enrich["dns"]
        a_ct = len(dns.get("a_records") or [])
        aaaa_ct = len(dns.get("aaaa_records") or [])
        cname_ct = len(dns.get("cname_records") or [])
        html += f'<div class="stat-card"><div class="stat-num">{a_ct}A / {aaaa_ct}AAAA / {cname_ct}CNAME</div><div class="stat-lbl">DNS Records</div></div>'
    if enrich.get("cve") and enrich["cve"].get("id"):
        cve = enrich["cve"]
        html += f'<div class="stat-card"><div class="stat-num">{_e(cve.get("id",""))}</div><div class="stat-lbl">CVE</div><div class="stat-sub">EPSS: {_e(str(round((cve.get("epss_score") or 0)*100,2)))}%{" [CISA KEV]" if cve.get("is_in_kev") else ""}</div></div>'
    if enrich.get("email_security"):
        es = enrich["email_security"]
        parts = []
        for k in ("spf", "dkim", "dmarc"):
            v = es.get(k)
            if v:
                parts.append(f'{k.upper()}: {_e(str(v)[:30])}')
        if parts:
            html += f'<div class="stat-card"><div class="stat-lbl">Email Security</div><div class="stat-sub">{" | ".join(parts)}</div></div>'
    html += '</div>'

    relations = data.get("relationships", [])
    if relations:
        html += '<h2>Relationships</h2><table><thead><tr><th>Target</th><th>Relationship</th></tr></thead><tbody>'
        seen_rel = set()
        for rr in relations:
            t = rr.get("target_ioc","")
            rl = rr.get("relationship","")
            key = f"{t}|{rl}"
            if key in seen_rel:
                continue
            seen_rel.add(key)
            html += f'<tr><td class="mono">{_e(t)}</td><td>{_e(rl)}</td></tr>'
        html += '</tbody></table>'

    html += '<div class="footer">Generated by IOC Lookup Platform — https://github.com/EclipseManic/ioc-lookup-platform</div></div></body></html>'
    return html

def _e(s):
    if s is None:
        return ""
    import html
    return html.escape(str(s))

@app.post("/api/export/stix")
async def export_stix(body: LookupRequest, db: AsyncSession = Depends(get_db)):
    task = await _resolve_task(body.ioc, body.task_id, db)
    response = _task_to_response(task).model_dump()

    bundle = build_stix_bundle(response)
    return bundle


@app.post("/api/export/misp")
async def export_misp(body: LookupRequest, db: AsyncSession = Depends(get_db)):
    task = await _resolve_task(body.ioc, body.task_id, db)
    response = _task_to_response(task).model_dump()

    event = build_misp_event(response)
    return event


class SIEMExportRequest(BaseModel):
    ioc: str
    format: str = "splunk"
    task_id: str | None = None


@app.post("/api/export/siem")
async def export_siem_endpoint(body: SIEMExportRequest, db: AsyncSession = Depends(get_db)):
    task = await _resolve_task(body.ioc, body.task_id, db)
    response = _task_to_response(task).model_dump()

    try:
        text = export_siem(response, body.format)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    content_type = {
        "splunk": "text/plain",
        "ecs": "application/x-ndjson",
        "leef": "text/plain",
    }.get(body.format, "text/plain")
    return PlainTextResponse(text, media_type=content_type)


@app.post("/api/export/csv")
async def export_csv(body: LookupRequest, db: AsyncSession = Depends(get_db)):
    task = await _resolve_task(body.ioc, body.task_id, db)

    results = [r.model_dump() for r in task.results]
    csv_content = results_to_csv(results)
    return PlainTextResponse(csv_content, media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=ioc_report.csv"})


# --- Webhooks ---

class WebhookCreate(BaseModel):
    url: str
    events: list[str] = ["lookup.complete"]
    secret: str | None = None


@app.get("/api/webhooks", response_model=list[WebhookResponse])
async def get_webhooks():
    if not settings.webhooks_enabled:
        raise HTTPException(status_code=403, detail="Webhooks are disabled")
    return await list_webhooks()


@app.post("/api/webhooks", response_model=WebhookResponse)
async def create_webhook(body: WebhookCreate):
    if not settings.webhooks_enabled:
        raise HTTPException(status_code=403, detail="Webhooks are disabled")
    if not body.secret or len(body.secret.strip()) < 16:
        raise HTTPException(status_code=400, detail="A signing secret of at least 16 characters is required")
    try:
        result = await add_webhook(body.url, body.events, body.secret)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/webhooks/{webhook_id}", response_model=StatusResponse)
async def delete_webhook(webhook_id: str):
    if not settings.webhooks_enabled:
        raise HTTPException(status_code=403, detail="Webhooks are disabled")
    ok = await remove_webhook(webhook_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return StatusResponse(status="deleted")


# --- Save Lookup Result ---

async def _auto_score_ioc(normalized: str, ioc_id: int, db: AsyncSession, ioc_type: str | None = None) -> bool:
    from app.backend.cache import cache_key
    from app.backend.pipeline import cache as _cache

    task = None
    effective_type = ioc_type or classify_ioc(normalized)
    ck = cache_key("save", effective_type, normalized)
    if _cache is not None:
        cached = await _cache.get(ck)
        if cached and cached.get("task_id"):
            cached_task = await get_task_redis(cached["task_id"])
            if cached_task is not None and cached_task.status == "done":
                task = cached_task

    if task is None:
        task = await run_analysis(
            normalized,
            fp_override=normalized in await _fetch_fp_overrides(db),
            ioc_type_override=effective_type if effective_type in SUPPORTED_IOC_TYPES and effective_type != "unknown" else None,
            password_prehashed=effective_type == "password",
        )

    if task.status == "done" and task.composite:
        # Same fields and payload the pipeline persists (DV-1: the
        # final_assessment verdict, not the reputation-only composite), so a
        # saved result never differs from the live one.
        score, verdict, confidence = persisted_verdict_fields(task)
        await upsert_lookup_result(
            db,
            ioc_id=ioc_id,
            task_id=task.task_id,
            composite_score=score,
            composite_verdict=verdict,
            composite_confidence=confidence,
            full_response=json.dumps(task_response_payload(task), default=str),
            source_count=len(task.results),
        )
        return True
    return False


@app.post("/api/save", response_model=SaveResponse)
async def save_lookup_result(body: LookupRequest, db: AsyncSession = Depends(get_db)):
    normalized = _normalize_ioc(body.ioc)
    parsed_type, parsed_value = parse_typed_ioc(normalized)
    if parsed_type is not None and body.ioc_type is None:
        normalized = parsed_value
    input_type = body.ioc_type or parsed_type
    normalized_info = normalize_ioc(normalized, expected_type=input_type)
    if not normalized_info.valid:
        raise HTTPException(status_code=400, detail="Unrecognizable IOC format")
    _reject_ambiguous_ingress(body.ioc, body.ioc_type, normalized_info)
    normalized = normalized_info.value
    prehashed_password = input_type == "password_sha1" or (
        input_type == "password" and is_password_digest(normalized)
    )
    ioc_type = "password" if prehashed_password else (input_type or normalized_info.ioc_type)
    if ioc_type == "password" or classify_ioc(normalized) == "password":
        normalized = password_digest(normalized, already_digest=prehashed_password)
        ioc_type = "password"
    if ioc_type not in SUPPORTED_IOC_TYPES:
        raise HTTPException(status_code=400, detail="Unsupported IOC type")

    existing = await db.execute(select(IOC).where(IOC.value == normalized))
    ioc = existing.scalar_one_or_none()
    if not ioc:
        ioc = IOC(value=normalized, ioc_type=ioc_type)
        db.add(ioc)
        await db.flush()
    ioc_id = ioc.id

    task = None
    if body.task_id:
        task = await get_task_redis(body.task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="Task not found")
    else:
        from app.backend.cache import cache_key
        from app.backend.pipeline import cache as _cache

        ck = cache_key("save", ioc_type, normalized)
        if _cache is not None:
            cached = await _cache.get(ck)
            if cached and cached.get("task_id"):
                cached_task = await get_task_redis(cached["task_id"])
                if cached_task is not None and cached_task.status == "done":
                    task = cached_task

    if task is not None:
        task_ioc = refang(task.normalized or task.ioc_value or "").lower()
        if task_ioc and task_ioc != normalized.lower():
            raise HTTPException(status_code=409, detail="Task does not belong to this IOC")
        if task.status != "done":
            raise HTTPException(status_code=425, detail="Analysis not yet complete")
        existing_result = await db.execute(
            select(LookupResult).where(LookupResult.task_id == task.task_id)
        )
        if existing_result.scalar_one_or_none():
            return SaveResponse(status="saved", ioc_id=ioc_id)

    if task is None:
        task = await run_analysis(
            normalized,
            fp_override=normalized in await _fetch_fp_overrides(db),
            ioc_type_override=ioc_type if ioc_type != "unknown" else None,
            password_prehashed=ioc_type == "password",
        )

    if task.status == "done" and task.composite:
        # Same fields and payload the pipeline persists (DV-1: the
        # final_assessment verdict, not the reputation-only composite), so a
        # saved result never differs from the live one.
        score, verdict, confidence = persisted_verdict_fields(task)
        await upsert_lookup_result(
            db,
            ioc_id=ioc_id,
            task_id=task.task_id,
            composite_score=score,
            composite_verdict=verdict,
            composite_confidence=confidence,
            full_response=json.dumps(task_response_payload(task), default=str),
            source_count=len(task.results),
        )

    return SaveResponse(status="saved", ioc_id=ioc_id)


@app.get("/api/screenshot")
async def proxy_screenshot(scan_id: str):
    """Secure backend proxy for urlscan.io screenshots to avoid CSP issues and analyst IP leakage."""
    if not re.match(r"^[a-zA-Z0-9\-]{10,64}$", scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    url = f"https://urlscan.io/screenshots/{scan_id}.png"
    client = _get_http_client()
    try:
        resp = await client.get(url, timeout=10)
        if resp.status_code == 200:
            return Response(
                content=resp.content,
                media_type="image/png",
                headers={"Cache-Control": "private, no-store"},
            )
        raise HTTPException(status_code=resp.status_code, detail="Screenshot not available from upstream")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch screenshot: {exc}")


# --- Local React UI ---

ROOT = Path(__file__).resolve().parent.parent.parent
ui_dist_dir = ROOT / "ui" / "dist"
ui_assets_dir = ui_dist_dir / "assets"

if ui_assets_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(ui_assets_dir)), name="ui-assets")


@app.get("/")
async def index():
    index_file = ui_dist_dir / "index.html"
    if not index_file.exists():
        return PlainTextResponse(
            "The local UI has not been built. Run `cd ui`, `npm install`, and `npm run build`.",
            status_code=503,
        )
    return FileResponse(str(index_file))
