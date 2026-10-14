import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import random
import socket
import time
import uuid
from typing import Optional
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken

from app.backend.config import settings
from app.backend.database import async_session, retry_sqlite_commit
from app.backend.http_client import get_client, resolve_public_url
from app.backend.logger import get_logger
from app.backend.models import Webhook as WebhookModel

logger = get_logger("webhooks")

_MAX_WEBHOOKS = 50
_DEFAULT_EVENTS = ["lookup.complete"]
_RETRY_ATTEMPTS = 3
_BASE_DELAY = 1.0
_WEBHOOK_TIMEOUT = 10.0
_MAX_PENDING_DISPATCH = 50

_pending_dispatch: set[asyncio.Task] = set()


def _secret_cipher() -> Fernet | None:
    key_material = settings.webhook_secret_key.strip()
    if not key_material:
        return None
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(key_material.encode()).digest()))


def _protect_secret(secret: str | None) -> str | None:
    if not secret:
        return None
    cipher = _secret_cipher()
    if cipher is None:
        raise ValueError("WEBHOOK_SECRET_KEY is required before storing a webhook secret")
    return cipher.encrypt(secret.encode()).decode()


def _unprotect_secret(value: str | None) -> str | None:
    if not value:
        return None
    cipher = _secret_cipher()
    if not cipher:
        return None
    if not value.startswith("gAAAA"):
        logger.error("Legacy plaintext webhook secret rejected")
        return None
    try:
        return cipher.decrypt(value.encode()).decode()
    except InvalidToken:
        logger.error("Webhook secret could not be decrypted")
        return None


def spawn_lookup_dispatch(task_id: str, ioc_value: str, verdict: str, score: float) -> Optional[asyncio.Task]:
    """Track a fire-and-forget webhook dispatch; cap concurrent pending dispatches.

    MAIN-13 / MAIN-22: dispatches are tracked so they can be cancelled on
    shutdown, and a cap prevents unbounded task buildup under load.
    """
    if len(_pending_dispatch) >= _MAX_PENDING_DISPATCH:
        logger.warning("Webhook dispatch cap reached (%d); dropping dispatch for %s", _MAX_PENDING_DISPATCH, task_id)
        return None

    task = asyncio.ensure_future(dispatch_lookup_complete(task_id, ioc_value, verdict, score))

    def _done(t: asyncio.Task):
        _pending_dispatch.discard(t)

    _pending_dispatch.add(task)
    task.add_done_callback(_done)
    return task


async def queue_lookup_dispatch(task_id: str, ioc_value: str, verdict: str, score: float) -> Optional[asyncio.Task]:
    """Queue a completion webhook only when a matching target exists.

    The inexpensive database check is awaited so callers do not leave a
    fire-and-forget database task behind when the application has no webhooks.
    Actual HTTP delivery remains asynchronous.
    """
    if not settings.webhooks_enabled:
        return None
    try:
        targets = await list_webhooks()
    except Exception as exc:
        logger.error("Could not inspect configured webhooks: %s", exc)
        return None

    if not any("lookup.complete" in target.get("events", _DEFAULT_EVENTS) for target in targets):
        return None
    return spawn_lookup_dispatch(task_id, ioc_value, verdict, score)


async def shutdown_webhook_tasks():
    """Cancel and await all in-flight webhook dispatch tasks (MAIN-13)."""
    tasks = list(_pending_dispatch)
    for t in tasks:
        t.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    _pending_dispatch.clear()


async def _resolve_hosts(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    loop = asyncio.get_running_loop()
    infos = await loop.run_in_executor(
        None,
        socket.getaddrinfo,
        host,
        None,
        0,
        socket.AF_UNSPEC,
        socket.SOCK_STREAM,
    )
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        address = info[4][0]
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
        if parsed not in addresses:
            addresses.append(parsed)
    return addresses


async def _resolve_host(host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    addresses = await _resolve_hosts(host)
    return addresses[0] if addresses else None


async def _validate_webhook_url(url: str) -> Optional[str]:
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        return "Webhook URL must use HTTPS"
    host = parsed.hostname
    if not host:
        return "Invalid webhook URL"
    if parsed.username is not None or parsed.password is not None:
        return "Webhook URL userinfo is not allowed"
    try:
        addresses = await _resolve_hosts(host)
        if not addresses or any(not address.is_global for address in addresses):
            return "Webhook URL must point to a public address"
    except Exception:
        return "Could not resolve webhook URL"
    return None



async def add_webhook(url: str, events: Optional[list[str]] = None, secret: Optional[str] = None) -> dict:
    if settings.webhooks_enabled and not secret:
        raise ValueError("A per-webhook signing secret is required")
    err = await _validate_webhook_url(url)
    if err:
        raise ValueError(err)
    current = await list_webhooks()
    if len(current) >= _MAX_WEBHOOKS:
        raise ValueError(f"Maximum {_MAX_WEBHOOKS} webhooks allowed")

    wh_id = uuid.uuid4().hex[:12]
    events_str = json.dumps(events or _DEFAULT_EVENTS)
    async with async_session() as session:
        wh = WebhookModel(id=wh_id, url=url, events=events_str, secret=_protect_secret(secret))
        session.add(wh)
        await retry_sqlite_commit(session)
        await session.refresh(wh)
        created_at = wh.created_at.isoformat() if wh.created_at else ""
    return {"id": wh_id, "url": url, "events": events or _DEFAULT_EVENTS, "has_secret": bool(secret), "created_at": created_at}


async def remove_webhook(webhook_id: str) -> bool:
    async with async_session() as session:
        wh = await session.get(WebhookModel, webhook_id)
        if wh is None:
            return False
        await session.delete(wh)
        await retry_sqlite_commit(session)
        return True


async def list_webhooks(include_secret: bool = False) -> list[dict]:
    async with async_session() as session:
        from sqlalchemy import select
        result = await session.execute(select(WebhookModel).order_by(WebhookModel.created_at))
        rows = result.scalars().all()
        targets = []
        for row in rows:
            target = {
                "id": row.id,
                "url": row.url,
                "events": json.loads(row.events),
                "has_secret": bool(row.secret),
                "created_at": row.created_at.isoformat() if row.created_at else "",
            }
            if include_secret:
                target["secret"] = _unprotect_secret(row.secret)
            targets.append(target)
        return targets


def _sign_payload(payload: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


async def dispatch_event(event: str, data: dict):
    targets = await list_webhooks(include_secret=True)
    if not targets:
        return

    wh_targets = [t for t in targets if event in t.get("events", _DEFAULT_EVENTS)]
    if not wh_targets:
        return

    client = get_client()

    for wh in wh_targets:
        secret = wh.get("secret")
        if not secret:
            logger.error("Skipping webhook %s because its signing secret is unavailable", wh["id"])
            continue
        pinned_target = await resolve_public_url(wh["url"], resolver=_resolve_hosts)
        if pinned_target is None:
            logger.warning("Skipping webhook %s: unsafe or unresolved target", wh["id"])
            continue
        pinned_url, pin_headers, extensions = pinned_target
        event_id = uuid.uuid4().hex
        timestamp = str(int(time.time()))
        envelope = {
            "event": event,
            "event_id": event_id,
            "timestamp": timestamp,
            **data,
        }
        payload = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
        headers = {
            **pin_headers,
            "Content-Type": "application/json",
            "X-Webhook-Event": event,
            "X-Webhook-Event-ID": event_id,
            "X-Webhook-Timestamp": timestamp,
            "X-Webhook-Signature": _sign_payload(timestamp.encode() + b"." + payload, secret),
        }

        for attempt in range(_RETRY_ATTEMPTS):
            try:
                resp = await client.post(
                    pinned_url,
                    content=payload,
                    headers=headers,
                    timeout=_WEBHOOK_TIMEOUT,
                    follow_redirects=False,
                    extensions=extensions,
                )
                if resp.is_success:
                    break
                logger.warning("Webhook %s attempt %d/%d returned %d", wh["id"], attempt + 1, _RETRY_ATTEMPTS, resp.status_code)
            except Exception as exc:
                logger.error("Webhook %s attempt %d/%d failed: %s", wh["id"], attempt + 1, _RETRY_ATTEMPTS, exc)
            if attempt < _RETRY_ATTEMPTS - 1:
                delay = _BASE_DELAY * (2 ** attempt) + random.uniform(0, 0.5)
                await asyncio.sleep(delay)


async def dispatch_lookup_complete(task_id: str, ioc_value: str, verdict: str, score: float):
    base_url = settings.base_url.rstrip("/") if settings.base_url else ""
    await dispatch_event("lookup.complete", {
        "task_id": task_id,
        "ioc_value": ioc_value,
        "verdict": verdict,
        "score": score,
        "result_url": f"{base_url}/api/tasks/{task_id}/result",
    })
