"""Isolated Google sign-in routes; this module does not authorize chat data."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi import HTTPException

from google_oidc import GoogleOIDCClient, OIDCError, constant_time_equal, digest

router = APIRouter(prefix="/auth", tags=["authentication"])
TX_COOKIE = "__Host-marina_oidc_txn"
SESSION_COOKIE = "__Host-marina_session"
CSRF_COOKIE = "__Host-marina_csrf"
TX_SECONDS = 300
IDLE_SECONDS = 12 * 60 * 60
ABSOLUTE_SECONDS = 30 * 24 * 60 * 60


class CallbackQueryRedactionMiddleware:
    """Keep OAuth code/state out of the ASGI scope used by access loggers."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and scope.get("path") in {
                "/auth/google/callback", "/auth/email/confirm"}:
            state = scope.setdefault("state", {})
            key = "oidc_callback_query" if scope["path"] == "/auth/google/callback" else "email_confirmation_query"
            state[key] = scope.get("query_string", b"")
            scope["query_string"] = b""
        await self.app(scope, receive, send)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(value: datetime | None = None) -> str:
    return (value or _now()).isoformat(timespec="seconds")


def _config() -> tuple[str, str, str, str] | None:
    client_id = os.getenv("GOOGLE_OIDC_CLIENT_ID", "").strip()
    secret = os.getenv("GOOGLE_OIDC_CLIENT_SECRET", "")
    redirect = os.getenv("GOOGLE_OIDC_REDIRECT_URI", "").strip()
    canonical = os.getenv("GENESIS_CANONICAL_ORIGIN", "").strip()
    parsed = urlsplit(redirect)
    if not client_id or not secret or parsed.scheme != "https" or not parsed.hostname or parsed.path != "/auth/google/callback" or parsed.query or parsed.fragment or parsed.username or parsed.password:
        return None
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if canonical and canonical.rstrip("/") != origin:
        return None
    return client_id, secret, redirect, origin


def _database():
    # Delayed import avoids a main <-> router cycle. User-data routes resolve
    # this server-side account session; the Phase 1 owner namespace stays separate.
    from main import connect_db
    return connect_db()


def _client(request: Request, cfg):
    fake = getattr(request.app.state, "google_oidc_client", None)
    if fake is not None:
        return fake
    return GoogleOIDCClient(cfg[0], cfg[1], cfg[2])


def _cookie(request: Request, name: str) -> str:
    return request.cookies.get(name, "")


def _session(request: Request):
    raw = _cookie(request, SESSION_COOKIE)
    if not raw or len(raw) > 256:
        return None
    token_hash = digest(raw)
    now = _stamp()
    with _database() as db:
        if request.url.path in {"/auth/google/start", "/auth/google/callback",
                "/auth/email/sign-in", "/auth/email/recovery", "/auth/email/confirm"}:
            from main import cleanup_auth_retention
            cleanup_auth_retention(db, limit=250)
        row = db.execute("""SELECT s.token_hash,s.account_id,s.csrf_token_hash,s.idle_expires_at,
            s.absolute_expires_at,a.status,e.email_normalized FROM auth_sessions s
            JOIN accounts a ON a.id=s.account_id LEFT JOIN account_emails e
            ON e.account_id=a.id AND e.is_primary=1 AND e.verified_at IS NOT NULL
            WHERE s.token_hash=? AND s.revoked_at IS NULL""", (token_hash,)).fetchone()
        if not row or row["status"] != "active" or row["idle_expires_at"] <= now or row["absolute_expires_at"] <= now:
            if row:
                db.execute("UPDATE auth_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL", (now, token_hash))
            return None
        idle = min(_now() + timedelta(seconds=IDLE_SECONDS), datetime.fromisoformat(row["absolute_expires_at"]))
        db.execute("UPDATE auth_sessions SET last_seen_at=?,idle_expires_at=? WHERE token_hash=?",
            (now, _stamp(idle), token_hash))
        return {"account_id": row["account_id"], "csrf_hash": row["csrf_token_hash"], "email": row["email_normalized"], "token_hash": token_hash}


def _set_session_cookies(response, raw_session: str, raw_csrf: str) -> None:
    response.set_cookie(SESSION_COOKIE, raw_session, max_age=ABSOLUTE_SECONDS,
        httponly=True, secure=True, samesite="lax", path="/")
    response.set_cookie(CSRF_COOKIE, raw_csrf, max_age=ABSOLUTE_SECONDS,
        httponly=False, secure=True, samesite="strict", path="/")


def _clear(response, name: str, *, httponly: bool) -> None:
    response.set_cookie(name, "", max_age=0, expires=0, httponly=httponly,
        secure=True, samesite="lax" if httponly else "strict", path="/")


@router.get("/status")
async def auth_status(request: Request):
    session = _session(request)
    return JSONResponse({"configured": _config() is not None,
        "authenticated": session is not None,
        "email": session["email"] if session else None,
        "data_access": session is not None,
        "notice": ("New conversations, preferences, and approved memories sync for this account. Pre-account data remains separate."
            if session else "Sign in to sync new conversations, preferences, and approved memories across devices. Existing anonymous data remains separate.")},
        headers={"Cache-Control": "no-store"})


@router.post("/delete-account")
async def delete_account_route(request: Request):
    """Explicit account deletion; default-off and protected by session CSRF."""
    if os.getenv("ACCOUNT_DELETION_ENABLED", "0") != "1":
        return JSONResponse({"detail": "Account deletion is not enabled."}, status_code=503,
            headers={"Cache-Control": "no-store"})
    if os.getenv("GENESIS_ENV", "") != "test":
        return JSONResponse({"detail": "Account deletion is unavailable until production storage cleanup is approved and verified."},
            status_code=503, headers={"Cache-Control": "no-store"})
    session = _session(request)
    origin = request.headers.get("origin", "")
    expected_origin = os.getenv("GENESIS_CANONICAL_ORIGIN", "").rstrip("/")
    csrf_cookie = _cookie(request, CSRF_COOKIE)
    csrf_header = request.headers.get("x-marina-csrf", "")
    if (not session or not expected_origin or origin.rstrip("/") != expected_origin or not csrf_cookie or not csrf_header
            or not constant_time_equal(csrf_cookie, csrf_header)
            or not constant_time_equal(digest(csrf_cookie), session["csrf_hash"])):
        return JSONResponse({"detail": "Account deletion request could not be verified."}, status_code=403,
            headers={"Cache-Control": "no-store"})
    try:
        payload = await request.json()
    except Exception:
        payload = None
    if not isinstance(payload, dict) or payload.get("confirm") != "DELETE":
        return JSONResponse({"detail": "Explicit DELETE confirmation is required."}, status_code=400,
            headers={"Cache-Control": "no-store"})
    from retention import delete_account
    from main import DB_PATH, image_service
    result = await delete_account(DB_PATH, session["account_id"], image_cleanup=image_service.delete_account_images)
    if result["status"] == "active_conversation":
        return JSONResponse({"detail": "Finish active conversations before deleting this account."}, status_code=409,
            headers={"Cache-Control": "no-store"})
    if result["status"] == "pending_image_cleanup":
        return JSONResponse({"detail": "Account deletion is pending secure storage cleanup."}, status_code=503,
            headers={"Cache-Control": "no-store"})
    if not result["deleted"]:
        return JSONResponse({"detail": "Account not found."}, status_code=404,
            headers={"Cache-Control": "no-store"})
    response = JSONResponse({"deleted": True}, headers={"Cache-Control": "no-store"})
    _clear(response, SESSION_COOKIE, httponly=True)
    _clear(response, CSRF_COOKIE, httponly=False)
    return response


@router.get("/google/start")
async def google_start(request: Request):
    cfg = _config()
    if cfg is None:
        return JSONResponse({"detail": "Google sign-in is not configured."}, status_code=503)
    state, nonce, verifier, binding = (secrets.token_urlsafe(n) for n in (32, 32, 48, 32))
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    created, expires = _stamp(), _stamp(_now() + timedelta(seconds=TX_SECONDS))
    with _database() as db:
        from main import (GOOGLE_START_GLOBAL_PER_5M, GOOGLE_START_IP_PER_5M,
                          cleanup_auth_retention, take_security_rate_limit)
        db.execute("BEGIN IMMEDIATE")
        cleanup_auth_retention(db, limit=250)
        db.execute("DELETE FROM oauth_transactions WHERE state_hash IN (SELECT state_hash FROM oauth_transactions WHERE expires_at<=? OR consumed_at IS NOT NULL LIMIT 250)", (created,))
        client_ip = getattr(request.state, "client_ip", "unknown")
        if not (take_security_rate_limit(db, category="google_start_ip_5m", value=client_ip,
                    limit=GOOGLE_START_IP_PER_5M, window_seconds=300)
                and take_security_rate_limit(db, category="google_start_global_5m", value="global",
                    limit=GOOGLE_START_GLOBAL_PER_5M, window_seconds=300)):
            return JSONResponse({"detail": "Google sign-in is temporarily unavailable."}, status_code=429,
                headers={"Cache-Control": "no-store", "Retry-After": "300"})
        if db.execute("SELECT COUNT(*) FROM oauth_transactions").fetchone()[0] >= 1000:
            return JSONResponse({"detail": "Google sign-in is temporarily unavailable."}, status_code=429)
        db.execute("INSERT INTO oauth_transactions(state_hash,nonce_hash,binding_hash,verifier_hash,created_at,expires_at) VALUES(?,?,?,?,?,?)",
            (digest(state), digest(nonce), digest(binding), digest(verifier), created, expires))
    try:
        url = await _client(request, cfg).authorization_url(state=state, nonce=nonce, code_challenge=challenge)
    except OIDCError:
        return JSONResponse({"detail": "Google sign-in is temporarily unavailable."}, status_code=503)
    tx = base64.urlsafe_b64encode(json.dumps({"s": state, "n": nonce, "v": verifier, "b": binding}, separators=(",", ":")).encode()).rstrip(b"=").decode()
    response = RedirectResponse(url, status_code=302, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
    response.set_cookie(TX_COOKIE, tx, max_age=TX_SECONDS, httponly=True, secure=True, samesite="lax", path="/")
    return response


@router.get("/google/callback")
async def google_callback(request: Request):
    raw_query = request.scope.get("state", {}).get("oidc_callback_query", b"")
    try:
        parsed = parse_qs(raw_query.decode("ascii"), keep_blank_values=True, strict_parsing=True)
        if any(len(values) != 1 for values in parsed.values()):
            raise ValueError("duplicate callback parameter")
        state = parsed.get("state", [""])[0]
        code = parsed.get("code", [""])[0]
        error = parsed.get("error", [""])[0]
    except (UnicodeDecodeError, ValueError):
        state, code, error = "", "", "invalid_callback"
    cfg = _config()
    response_headers = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}
    def failure(status: int = 400):
        response = JSONResponse({"detail": "Google sign-in could not be completed."}, status_code=status, headers=response_headers)
        _clear(response, TX_COOKIE, httponly=True)
        return response
    if cfg is None or error or not state or not code or len(state) > 512 or len(code) > 4096:
        return failure(503 if cfg is None else 400)
    previous_session = _session(request)
    try:
        packed = _cookie(request, TX_COOKIE)
        if len(packed) > 4096:
            return failure()
        padded = packed + "=" * (-len(packed) % 4)
        values = json.loads(base64.urlsafe_b64decode(padded.encode()))
        cookie_state, nonce, verifier, binding = (values[key] for key in ("s", "n", "v", "b"))
        if not all(isinstance(v, str) and 20 <= len(v) <= 128 for v in (cookie_state, nonce, verifier, binding)):
            return failure()
    except Exception:
        return failure()
    if not constant_time_equal(state, cookie_state):
        return failure()
    now = _stamp()
    with _database() as db:
        row = db.execute("SELECT nonce_hash,binding_hash,verifier_hash,expires_at,consumed_at FROM oauth_transactions WHERE state_hash=?",
            (digest(state),)).fetchone()
        if not row or row["consumed_at"] or row["expires_at"] <= now or not all((
            constant_time_equal(row["nonce_hash"], digest(nonce)),
            constant_time_equal(row["binding_hash"], digest(binding)),
            constant_time_equal(row["verifier_hash"], digest(verifier)))):
            return failure()
        changed = db.execute("UPDATE oauth_transactions SET consumed_at=? WHERE state_hash=? AND consumed_at IS NULL AND expires_at>?",
            (now, digest(state), now)).rowcount
        if changed != 1:
            return failure()
    try:
        claims = await _client(request, cfg).exchange_and_verify(code=code, code_verifier=verifier, nonce=nonce)
        if not isinstance(claims, dict) or claims.get("email_verified") is not True:
            raise OIDCError("oidc_claims")
        subject, email = claims.get("sub"), claims.get("email")
        if not isinstance(subject, str) or not subject or not isinstance(email, str) or "@" not in email:
            raise OIDCError("oidc_claims")
        email = email.strip().casefold()
        with _database() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = db.execute("SELECT account_id FROM external_identities WHERE provider='google' AND subject=?", (subject,)).fetchone()
            if identity:
                account_id = identity["account_id"]
                account = db.execute("SELECT status FROM accounts WHERE id=?", (account_id,)).fetchone()
                if not account or account["status"] != "active":
                    raise OIDCError("account_unavailable")
                existing_email = db.execute("SELECT account_id FROM account_emails WHERE email_normalized=? AND verified_at IS NOT NULL", (email,)).fetchone()
                if existing_email and existing_email["account_id"] != account_id:
                    raise OIDCError("account_conflict")
                if not existing_email:
                    db.execute("UPDATE account_emails SET is_primary=0 WHERE account_id=? AND is_primary=1", (account_id,))
                    db.execute("INSERT INTO account_emails(id,account_id,email_normalized,verified_at,is_primary,created_at) VALUES(?,?,?,?,?,?)",
                        (str(uuid.uuid4()), account_id, email, now, 1, now))
            else:
                if db.execute("SELECT 1 FROM account_emails WHERE email_normalized=? AND verified_at IS NOT NULL", (email,)).fetchone():
                    raise OIDCError("account_conflict")
                account_id = str(uuid.uuid4())
                db.execute("INSERT INTO accounts(id,status,created_at,updated_at) VALUES(?,'active',?,?)", (account_id, now, now))
                db.execute("INSERT INTO external_identities(id,account_id,provider,subject,email_snapshot,email_verified_at,created_at) VALUES(?,?,?,?,?,?,?)",
                    (str(uuid.uuid4()), account_id, "google", subject, email, now, now))
                db.execute("INSERT INTO account_emails(id,account_id,email_normalized,verified_at,is_primary,created_at) VALUES(?,?,?,?,?,?)",
                    (str(uuid.uuid4()), account_id, email, now, 1, now))
            raw_session, raw_csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            session_hash = digest(raw_session)
            db.execute("INSERT INTO auth_sessions(token_hash,account_id,csrf_token_hash,auth_method,created_at,last_seen_at,idle_expires_at,absolute_expires_at) VALUES(?,?,?,'google',?,?,?,?)",
                (session_hash, account_id, digest(raw_csrf), now, now,
                 _stamp(_now() + timedelta(seconds=IDLE_SECONDS)), _stamp(_now() + timedelta(seconds=ABSOLUTE_SECONDS))))
            if previous_session:
                db.execute("UPDATE auth_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
                    (now, previous_session["token_hash"]))
            db.commit()
    except OIDCError:
        return failure()
    except sqlite3.IntegrityError:
        return failure()
    except Exception:
        return failure(503)
    response = RedirectResponse("/", status_code=303, headers=response_headers)
    _set_session_cookies(response, raw_session, raw_csrf)
    _clear(response, TX_COOKIE, httponly=True)
    return response


@router.post("/logout")
async def logout(request: Request):
    cfg = _config()
    origin = request.headers.get("origin", "")
    session = _session(request)
    csrf_cookie = _cookie(request, CSRF_COOKIE)
    csrf_header = request.headers.get("x-marina-csrf", "")
    configured_origin = os.getenv("GENESIS_CANONICAL_ORIGIN", "").strip()
    if not configured_origin and cfg:
        configured_origin = cfg[3]
    parsed_origin = urlsplit(configured_origin)
    expected_origin = (f"https://{parsed_origin.netloc}"
        if parsed_origin.scheme == "https" and parsed_origin.hostname and parsed_origin.path in ("", "/")
        and not parsed_origin.query and not parsed_origin.fragment and not parsed_origin.username and not parsed_origin.password
        else "")
    valid = bool(expected_origin and session and origin == expected_origin and csrf_cookie and csrf_header
        and constant_time_equal(csrf_cookie, csrf_header)
        and constant_time_equal(digest(csrf_cookie), session["csrf_hash"]))
    if not valid:
        return JSONResponse({"detail": "Request rejected."}, status_code=403,
            headers={"Cache-Control": "no-store"})
    with _database() as db:
        db.execute("UPDATE auth_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL", (_stamp(), session["token_hash"]))
    response = JSONResponse({"authenticated": False}, headers={"Cache-Control": "no-store"})
    _clear(response, SESSION_COOKIE, httponly=True)
    _clear(response, CSRF_COOKIE, httponly=False)
    return response
