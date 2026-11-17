"""Conservative network identity policy for Render Free synthetic staging."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit


class StagingHostError(ValueError):
    """Raised when the request Host does not match the configured staging origin."""


@dataclass(frozen=True)
class RenderRequestContext:
    public_origin: str
    public_host: str
    public_scheme: str
    client_ip: str


def render_staging_request_context(peer_ip: str, host_header: str, canonical_origin: str,
        forwarded_headers: object = None) -> RenderRequestContext:
    """Ignore proxy headers; derive security metadata from config and socket peer.

    Render terminates HTTPS before the ASGI process. Because Render does not
    publish a stable trusted proxy CIDR set for this service, forwarded headers
    are deliberately not consulted. Uvicorn must also run with proxy-header
    processing disabled. The canonical origin provides the external HTTPS
    scheme; the socket peer is used for IP quotas and security events.
    """
    del forwarded_headers  # Explicitly unused, including Forwarded and X-Forwarded-*.
    try:
        peer = ipaddress.ip_address(peer_ip).compressed
        origin = urlsplit(canonical_origin.rstrip("/"))
        authority = urlsplit("//" + host_header)
        host = (authority.hostname or "").rstrip(".").lower()
        origin_host = (origin.hostname or "").rstrip(".").lower()
        request_port = authority.port
        origin_port = origin.port
    except (TypeError, ValueError):
        raise StagingHostError("invalid") from None
    if (origin.scheme != "https" or not origin_host or origin.path not in {"", "/"}
            or origin.query or origin.fragment or origin.username or origin.password
            or origin_port not in {None, 443}):
        raise StagingHostError("invalid")
    if (not host or authority.username or authority.password or authority.path or authority.query or authority.fragment
            or request_port not in {None, 443} or host != origin_host):
        raise StagingHostError("host")
    return RenderRequestContext(
        public_origin=f"https://{origin.netloc}",
        public_host=origin.netloc,
        public_scheme="https",
        client_ip=peer,
    )


def render_staging_scope_is_https(scope_scheme: str, render_staging: bool,
        canonical_origin: str) -> bool:
    """Reflect Render's configured external HTTPS at the trusted edge."""
    if scope_scheme.lower() == "https":
        return True
    if not render_staging:
        return False
    try:
        return urlsplit(canonical_origin.rstrip("/")).scheme == "https"
    except ValueError:
        return False
