"""Google OIDC adapter. Network access occurs only when an explicit flow calls it.

Authlib supplies OAuth and JOSE primitives; claim policy and local transaction
binding are enforced here. Imports are lazy so offline tests need no live client.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import time
from urllib.parse import urlsplit

class OIDCError(Exception):
    """Sanitized authentication failure; never includes provider response data."""


def read_jwt_header(token: str) -> dict:
    """Read only bounded, untrusted JWT header fields before Authlib verifies it."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or len(parts[0]) > 2048:
        raise OIDCError("oidc_token_format")
    try:
        raw = base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
        header = json.loads(raw)
    except Exception as exc:
        raise OIDCError("oidc_token_format") from exc
    if not isinstance(header, dict) or header.get("alg") != "RS256":
        raise OIDCError("oidc_signature")
    if any(name in header for name in ("jku", "x5u", "crit")):
        raise OIDCError("oidc_signature")
    if not isinstance(header.get("kid"), str) or not header["kid"] or len(header["kid"]) > 256:
        raise OIDCError("oidc_signature")
    return header


def validate_id_token_claims(payload: dict, *, client_id: str, nonce: str, now: float | None = None) -> dict:
    """Apply explicit Google OIDC claim policy after Authlib signature verification."""
    now = time.time() if now is None else now
    if payload.get("iss") != GoogleOIDCClient.ISSUER:
        raise OIDCError("oidc_issuer")
    audience = payload.get("aud")
    if not (audience == client_id or isinstance(audience, list) and client_id in audience):
        raise OIDCError("oidc_audience")
    if isinstance(audience, list) and len(audience) > 1 and payload.get("azp") != client_id:
        raise OIDCError("oidc_audience")
    if payload.get("azp") is not None and payload.get("azp") != client_id:
        raise OIDCError("oidc_audience")
    exp, issued = payload.get("exp"), payload.get("iat")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not math.isfinite(exp) or exp <= now:
        raise OIDCError("oidc_expired")
    if isinstance(issued, bool) or not isinstance(issued, (int, float)) or not math.isfinite(issued) or issued > now + 60:
        raise OIDCError("oidc_claims")
    token_nonce = payload.get("nonce")
    if not isinstance(token_nonce, str) or not hmac.compare_digest(token_nonce, nonce):
        raise OIDCError("oidc_nonce")
    if payload.get("email_verified") is not True:
        raise OIDCError("oidc_claims")
    subject, email = payload.get("sub"), payload.get("email")
    if not isinstance(subject, str) or not subject or len(subject) > 255:
        raise OIDCError("oidc_claims")
    if not isinstance(email, str) or len(email) > 320 or "@" not in email:
        raise OIDCError("oidc_claims")
    return {"sub": subject, "email": email.strip().casefold(), "email_verified": True}


class GoogleOIDCClient:
    ISSUER = "https://accounts.google.com"
    DISCOVERY = ISSUER + "/.well-known/openid-configuration"
    ALLOWED_HOSTS = {"accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com"}

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, *, transport=None):
        self.client_id, self.client_secret, self.redirect_uri = client_id, client_secret, redirect_uri
        # Supplying a transport is intended for deterministic in-process tests.
        # Production callers leave it unset and retain normal verified TLS.
        self.transport = transport

    def _client_options(self, timeout: int) -> dict:
        options = {"timeout": timeout, "verify": True, "follow_redirects": False}
        if self.transport is not None:
            options["transport"] = self.transport
        return options

    async def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        try:
            import httpx
            from authlib.integrations.httpx_client import AsyncOAuth2Client
            async with httpx.AsyncClient(
                    **self._client_options(8)) as http:
                meta = await self._metadata(http)
            async with AsyncOAuth2Client(self.client_id, redirect_uri=self.redirect_uri) as oauth:
                url, returned_state = oauth.create_authorization_url(
                    meta["authorization_endpoint"], state=state, nonce=nonce,
                    code_challenge=code_challenge, code_challenge_method="S256",
                    scope="openid email")
            if returned_state != state:
                raise OIDCError("oidc_state")
            self._check_url(url)
            return url
        except OIDCError:
            raise
        except Exception as exc:
            raise OIDCError("oidc_unavailable") from exc

    async def exchange_and_verify(self, *, code: str, code_verifier: str, nonce: str) -> dict:
        try:
            import httpx
            from authlib.integrations.httpx_client import AsyncOAuth2Client
            from authlib.jose import JsonWebKey, jwt
            async with httpx.AsyncClient(**self._client_options(10)) as http:
                meta = await self._metadata(http)
            async with AsyncOAuth2Client(self.client_id, self.client_secret,
                    redirect_uri=self.redirect_uri, code_challenge_method="S256",
                    **self._client_options(10)) as client:
                token = await client.fetch_token(meta["token_endpoint"], code=code,
                    grant_type="authorization_code", code_verifier=code_verifier,
                    redirect_uri=self.redirect_uri)
                raw = token.get("id_token")
                if not isinstance(raw, str) or len(raw) > 16_384:
                    raise OIDCError("oidc_token_missing")
            async with httpx.AsyncClient(**self._client_options(10)) as http:
                jwks_response = await http.get(meta["jwks_uri"])
                jwks_response.raise_for_status()
                jwks = jwks_response.json()
            header = read_jwt_header(raw)
            key = JsonWebKey.import_key_set(jwks).find_by_kid(header["kid"])
            if key is None:
                raise OIDCError("oidc_signature")
            claims = jwt.decode(raw, key, claims_options={
                "iss": {"essential": True, "value": self.ISSUER},
                "aud": {"essential": True, "value": self.client_id},
                "exp": {"essential": True}, "iat": {"essential": True},
                "sub": {"essential": True}, "nonce": {"essential": True, "value": nonce},
            })
            claims.validate(leeway=60)
            return validate_id_token_claims(dict(claims), client_id=self.client_id, nonce=nonce)
        except OIDCError:
            raise
        except Exception as exc:
            # Do not leak tokens, codes, URLs, or provider response bodies.
            name = type(exc).__name__
            category = "oidc_signature" if name in {"JoseError", "BadSignatureError", "InvalidClaimError"} else "oidc_provider"
            raise OIDCError(category) from exc

    async def _metadata(self, http) -> dict:
        response = await http.get(self.DISCOVERY)
        response.raise_for_status()
        data = response.json()
        if data.get("issuer") != self.ISSUER:
            raise OIDCError("oidc_issuer")
        for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            self._check_url(data.get(name, ""))
        return data

    @classmethod
    def _check_url(cls, value: str) -> None:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or parsed.hostname not in cls.ALLOWED_HOSTS or parsed.username or parsed.password:
            raise OIDCError("oidc_endpoint")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


