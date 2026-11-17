"""Verified-email passwordless sign-in and recovery; no email provider is called by tests."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import re
import secrets
import smtplib
import ssl
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import parse_qs, urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from auth_routes import (
    ABSOLUTE_SECONDS, CSRF_COOKIE, IDLE_SECONDS, SESSION_COOKIE, _database,
    _now, _session, _set_session_cookies, _stamp,
)
from google_oidc import constant_time_equal, digest

router = APIRouter(prefix="/auth/email", tags=["email authentication"])
CONFIRM_COOKIE = "__Host-marina_email_confirm"
CONFIRM_CSRF_COOKIE = "__Host-marina_email_confirm_csrf"
LINK_LIFETIME_SECONDS = 10 * 60
IP_LIMIT = 10
EMAIL_LIMIT = 3
WINDOW_SECONDS = 60 * 60
EMAIL_COOLDOWN_SECONDS = 60
MAX_THROTTLE_ROWS = 100_000
MAX_ACTION_TOKEN_ROWS = 100_000

GENERIC_MESSAGE = "If this address can use this method, a message with next steps will arrive shortly."
GENERIC_FAILURE = "This link could not be completed. Request a new message if you still need access."
_LOCAL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$")


class EmailLinkRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)


def _normalize_email(value: str) -> str | None:
    value = value.strip()
    if len(value) > 320 or not value.isascii() or any(ord(ch) <= 32 or ord(ch) == 127 for ch in value):
        return None
    if value.count("@") != 1:
        return None
    local, domain = value.rsplit("@", 1)
    if (not local or len(local) > 64 or not _LOCAL_RE.fullmatch(local)
            or local.startswith(".") or local.endswith(".") or ".." in local):
        return None
    try:
        domain = domain.encode("idna").decode("ascii").casefold()
    except UnicodeError:
        return None
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", label) for label in labels):
        return None
    return f"{local.casefold()}@{domain}"


def _canonical_origin() -> str | None:
    value = os.getenv("GENESIS_CANONICAL_ORIGIN", "").strip()
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment or parsed.username or parsed.password):
        return None
    return f"https://{parsed.netloc}"


def _throttle_secret() -> bytes | None:
    value = os.getenv("EMAIL_AUTH_THROTTLE_SECRET", "")
    return value.encode("utf-8") if len(value.encode("utf-8")) >= 32 else None


def _bucket_hash(secret: bytes, kind: str, value: str) -> str:
    return hmac.new(secret, f"marina-email-auth:{kind}:{value}".encode(), hashlib.sha256).hexdigest()


def _take_bucket(db: sqlite3.Connection, *, key: str, kind: str, now: datetime,
                 limit: int, cooldown_seconds: int = 0) -> bool:
    stamp = _stamp(now)
    row = db.execute("SELECT window_started_at,attempts,cooldown_until FROM email_auth_throttles WHERE bucket_hash=?",
        (key,)).fetchone()
    if row is None:
        db.execute("INSERT INTO email_auth_throttles(bucket_hash,bucket_kind,window_started_at,attempts,cooldown_until,updated_at) VALUES(?,?,?,1,?,?)",
            (key, kind, stamp, _stamp(now + timedelta(seconds=cooldown_seconds)) if cooldown_seconds else None, stamp))
        return True
    start = datetime.fromisoformat(row["window_started_at"])
    if now >= start + timedelta(seconds=WINDOW_SECONDS):
        db.execute("UPDATE email_auth_throttles SET window_started_at=?,attempts=1,cooldown_until=?,updated_at=? WHERE bucket_hash=?",
            (stamp, _stamp(now + timedelta(seconds=cooldown_seconds)) if cooldown_seconds else None, stamp, key))
        return True
    if row["cooldown_until"] and row["cooldown_until"] > stamp:
        return False
    if int(row["attempts"]) >= limit:
        return False
    db.execute("UPDATE email_auth_throttles SET attempts=attempts+1,cooldown_until=?,updated_at=? WHERE bucket_hash=?",
        (_stamp(now + timedelta(seconds=cooldown_seconds)) if cooldown_seconds else None, stamp, key))
    return True


class SMTPEmailDelivery:
    """Explicitly configured implicit-TLS SMTP transport; never logs recipients or links."""
    def __init__(self, host: str, port: int, username: str, password: str, from_address: str):
        self.host, self.port, self.username, self.password, self.from_address = host, port, username, password, from_address

    @classmethod
    def from_env(cls):
        host = os.getenv("EMAIL_SMTP_HOST", "").strip()
        username = os.getenv("EMAIL_SMTP_USERNAME", "")
        password = os.getenv("EMAIL_SMTP_PASSWORD", "")
        from_address = os.getenv("EMAIL_FROM_ADDRESS", "").strip()
        try:
            port = int(os.getenv("EMAIL_SMTP_PORT", "465"))
        except ValueError:
            return None
        if not host or not username or not password or not from_address or port != 465:
            return None
        return cls(host, port, username, password, from_address)

    async def send(self, recipient: str, link: str) -> None:
        await asyncio.to_thread(self._send_sync, recipient, link)

    def _send_sync(self, recipient: str, link: str) -> None:
        message = EmailMessage()
        message["Subject"] = "Your Marina AI secure sign-in link"
        message["From"] = self.from_address
        message["To"] = recipient
        message.set_content(
            "Use this one-time link to continue with the sign-in or recovery action you requested. "
            "The link expires in 10 minutes. If you did not request it, ignore this message.\n\n" + link)
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(self.host, self.port, timeout=10, context=context) as smtp:
            smtp.login(self.username, self.password)
            smtp.send_message(message)


def _delivery(request: Request):
    fake_or_adapter = getattr(request.app.state, "email_delivery", None)
    return fake_or_adapter if fake_or_adapter is not None else SMTPEmailDelivery.from_env()


def _generic_response() -> JSONResponse:
    return JSONResponse({"message": GENERIC_MESSAGE}, status_code=202,
        headers={"Cache-Control": "no-store"})


def _email_auth_ready(request: Request) -> bool:
    return bool(_canonical_origin() and _throttle_secret() and _delivery(request))


@router.get("/status")
async def email_auth_status(request: Request):
    return JSONResponse({"configured": _email_auth_ready(request)},
        headers={"Cache-Control": "no-store"})


async def _request_link(request: Request, email_input: str, purpose: str):
    email = _normalize_email(email_input)
    origin = _canonical_origin()
    secret = _throttle_secret()
    sender = _delivery(request)
    if email is None or not origin or secret is None or sender is None:
        return _generic_response()
    if request.headers.get("origin", "") != origin:
        return JSONResponse({"detail": "Request rejected."}, status_code=403,
            headers={"Cache-Control": "no-store"})
    source_ip = getattr(request.state, "client_ip", "unknown")
    now = _now()
    raw_token = secrets.token_urlsafe(32)
    token_hash = digest(raw_token)
    expires_at = _stamp(now + timedelta(seconds=LINK_LIFETIME_SECONDS))
    allowed = False
    with _database() as db:
        from main import cleanup_auth_retention
        db.execute("BEGIN IMMEDIATE")
        cleanup_auth_retention(db, now_dt=now, limit=250)
        db.execute("DELETE FROM email_auth_throttles WHERE updated_at<?",
            (_stamp(now - timedelta(days=7)),))
        if (db.execute("SELECT COUNT(*) FROM email_auth_throttles").fetchone()[0] >= MAX_THROTTLE_ROWS
                or db.execute("SELECT COUNT(*) FROM email_action_tokens").fetchone()[0] >= MAX_ACTION_TOKEN_ROWS):
            return _generic_response()
        ip_allowed = _take_bucket(db, key=_bucket_hash(secret, "ip", source_ip), kind="ip", now=now,
            limit=IP_LIMIT)
        email_allowed = _take_bucket(db, key=_bucket_hash(secret, "email", email), kind="email", now=now,
            limit=EMAIL_LIMIT, cooldown_seconds=EMAIL_COOLDOWN_SECONDS)
        allowed = ip_allowed and email_allowed
        if allowed:
            identity = db.execute("""SELECT i.account_id,a.status FROM external_identities i
                JOIN accounts a ON a.id=i.account_id
                WHERE i.provider='email' AND i.subject=?""", (email,)).fetchone()
            account_id = identity["account_id"] if identity and identity["status"] == "active" else None
            db.execute("INSERT INTO email_action_tokens(token_hash,purpose,account_id,email_normalized,created_at,expires_at) VALUES(?,?,?,?,?,?)",
                (token_hash, purpose, account_id, email, _stamp(now), expires_at))
    if not allowed:
        return _generic_response()
    link = f"{origin}/auth/email/confirm?token={raw_token}"
    try:
        await sender.send(email, link)
    except Exception:
        # A failed delivery must not leave a redeemable, undisclosed token.
        with _database() as db:
            db.execute("UPDATE email_action_tokens SET consumed_at=? WHERE token_hash=? AND consumed_at IS NULL",
                (_stamp(), token_hash))
    return _generic_response()


@router.post("/sign-in")
async def request_email_sign_in(request: Request, body: EmailLinkRequest):
    return await _request_link(request, body.email, "sign_in")


@router.post("/recovery")
async def request_email_recovery(request: Request, body: EmailLinkRequest):
    return await _request_link(request, body.email, "recover_account")


def _find_valid_token(raw_token: str):
    if not raw_token or len(raw_token) > 128:
        return None
    with _database() as db:
        return db.execute("""SELECT token_hash,purpose,account_id,email_normalized,expires_at,consumed_at
            FROM email_action_tokens WHERE token_hash=? AND consumed_at IS NULL AND expires_at>? 
            AND purpose IN ('sign_in','recover_account')""", (digest(raw_token), _stamp())).fetchone()


def _clear_confirm_cookies(response):
    response.set_cookie(CONFIRM_COOKIE, "", max_age=0, expires=0, httponly=True,
        secure=True, samesite="lax", path="/")
    response.set_cookie(CONFIRM_CSRF_COOKIE, "", max_age=0, expires=0, httponly=False,
        secure=True, samesite="lax", path="/")


def _confirmation_html(*, csrf: str | None, failed: bool = False) -> HTMLResponse:
    headers = {
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    }
    if failed or not csrf:
        return HTMLResponse("<!doctype html><html><meta charset=utf-8><title>Marina AI</title>"
            f"<main><h1>{GENERIC_FAILURE}</h1><a href='/'>Return to Marina AI</a></main></html>",
            status_code=400, headers=headers)
    return HTMLResponse("<!doctype html><html lang=en><meta charset=utf-8><meta name=referrer content=no-referrer>"
        "<title>Confirm Marina AI sign-in</title><main><h1>Confirm this sign-in</h1>"
        "<p>This explicit confirmation completes the one-time email action.</p>"
        f"<form method=post action='/auth/email/confirm'><input type=hidden name=csrf value='{csrf}'>"
        "<button type=submit>Confirm and continue</button></form></main></html>", headers=headers)


@router.get("/confirm")
async def email_confirmation_page(request: Request):
    raw_query = request.scope.get("state", {}).get("email_confirmation_query", b"")
    if raw_query:
        try:
            values = parse_qs(raw_query.decode("ascii"), keep_blank_values=True, strict_parsing=True)
            if set(values) != {"token"} or len(values["token"]) != 1:
                raise ValueError("invalid link")
            raw_token = values["token"][0]
        except (UnicodeDecodeError, ValueError):
            response = _confirmation_html(csrf=None, failed=True)
            _clear_confirm_cookies(response)
            return response
        if not _find_valid_token(raw_token):
            response = _confirmation_html(csrf=None, failed=True)
            _clear_confirm_cookies(response)
            return response
        csrf = secrets.token_urlsafe(32)
        response = RedirectResponse("/auth/email/confirm", status_code=303, headers={
            "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
        response.set_cookie(CONFIRM_COOKIE, raw_token, max_age=LINK_LIFETIME_SECONDS,
            httponly=True, secure=True, samesite="lax", path="/")
        response.set_cookie(CONFIRM_CSRF_COOKIE, csrf, max_age=LINK_LIFETIME_SECONDS,
            httponly=False, secure=True, samesite="lax", path="/")
        return response
    raw_token = request.cookies.get(CONFIRM_COOKIE, "")
    csrf = request.cookies.get(CONFIRM_CSRF_COOKIE, "")
    if not csrf or not _find_valid_token(raw_token):
        response = _confirmation_html(csrf=None, failed=True)
        _clear_confirm_cookies(response)
        return response
    return _confirmation_html(csrf=csrf)


def _account_for_email_action(db: sqlite3.Connection, row, now: str):
    email, account_id, purpose = row["email_normalized"], row["account_id"], row["purpose"]
    identity = db.execute("""SELECT i.account_id,a.status FROM external_identities i
        JOIN accounts a ON a.id=i.account_id WHERE i.provider='email' AND i.subject=?""", (email,)).fetchone()
    if purpose == "recover_account":
        if not identity or identity["status"] != "active" or identity["account_id"] != account_id:
            return None
        db.execute("UPDATE auth_sessions SET revoked_at=? WHERE account_id=? AND revoked_at IS NULL", (now, account_id))
        db.execute("UPDATE email_action_tokens SET consumed_at=? WHERE account_id=? AND consumed_at IS NULL", (now, account_id))
        return account_id
    if account_id:
        if not identity or identity["status"] != "active" or identity["account_id"] != account_id:
            return None
        return account_id
    # New email identity creation is allowed only if this email is not already
    # attached to any account. In particular, it never claims a Google account.
    if db.execute("SELECT 1 FROM account_emails WHERE email_normalized=?", (email,)).fetchone():
        return None
    account_id = str(uuid.uuid4())
    db.execute("INSERT INTO accounts(id,status,created_at,updated_at) VALUES(?,'active',?,?)", (account_id, now, now))
    db.execute("INSERT INTO external_identities(id,account_id,provider,subject,email_snapshot,email_verified_at,created_at) VALUES(?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), account_id, "email", email, email, now, now))
    db.execute("INSERT INTO account_emails(id,account_id,email_normalized,verified_at,is_primary,created_at) VALUES(?,?,?,?,1,?)",
        (str(uuid.uuid4()), account_id, email, now, now))
    return account_id


@router.post("/confirm")
async def complete_email_confirmation(request: Request):
    origin = _canonical_origin()
    csrf_cookie = request.cookies.get(CONFIRM_CSRF_COOKIE, "")
    try:
        form = parse_qs((await request.body()).decode("ascii"), keep_blank_values=True, strict_parsing=True)
        csrf_values = form.get("csrf", [])
        csrf_form = csrf_values[0] if len(csrf_values) == 1 and len(form) == 1 else ""
    except (UnicodeDecodeError, ValueError):
        csrf_form = ""
    raw_token = request.cookies.get(CONFIRM_COOKIE, "")
    if (not origin or request.headers.get("origin", "") != origin or not csrf_cookie or not csrf_form
            or not constant_time_equal(csrf_cookie, csrf_form)):
        response = _confirmation_html(csrf=None, failed=True)
        _clear_confirm_cookies(response)
        return response
    previous_session = _session(request)
    session_value = csrf_value = None
    success = False
    with _database() as db:
        db.execute("BEGIN IMMEDIATE")
        token_hash = digest(raw_token) if raw_token and len(raw_token) <= 128 else ""
        row = db.execute("""SELECT token_hash,purpose,account_id,email_normalized,expires_at,consumed_at
            FROM email_action_tokens WHERE token_hash=?""", (token_hash,)).fetchone()
        now = _stamp()
        if row and not row["consumed_at"] and row["expires_at"] > now and row["purpose"] in ("sign_in", "recover_account"):
            consumed = db.execute("UPDATE email_action_tokens SET consumed_at=? WHERE token_hash=? AND consumed_at IS NULL AND expires_at>?",
                (now, token_hash, now)).rowcount
            if consumed == 1:
                account_id = _account_for_email_action(db, row, now)
                if account_id:
                    session_value, csrf_value = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                    absolute = _stamp(_now() + timedelta(seconds=ABSOLUTE_SECONDS))
                    idle = _stamp(_now() + timedelta(seconds=IDLE_SECONDS))
                    db.execute("INSERT INTO auth_sessions(token_hash,account_id,csrf_token_hash,auth_method,created_at,last_seen_at,idle_expires_at,absolute_expires_at) VALUES(?,?,?,'email',?,?,?,?)",
                        (digest(session_value), account_id, digest(csrf_value), now, now, idle, absolute))
                    if previous_session:
                        db.execute("UPDATE auth_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
                            (now, previous_session["token_hash"]))
                    success = True
        db.commit()
    if not success:
        response = _confirmation_html(csrf=None, failed=True)
        _clear_confirm_cookies(response)
        return response
    response = RedirectResponse("/", status_code=303, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
    _set_session_cookies(response, session_value, csrf_value)
    _clear_confirm_cookies(response)
    return response
