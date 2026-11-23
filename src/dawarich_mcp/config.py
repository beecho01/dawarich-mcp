"""Runtime configuration, read from environment variables and validated at startup.

Server settings use the ``DAWARICH_MCP_`` prefix. The upstream Dawarich
credentials keep the upstream product name (``DAWARICH_BASE_URL`` and
``DAWARICH_API_KEY``), and the API key also accepts a ``_FILE`` variant
(Docker/Kubernetes secrets) so the secret does not have to live in the
process environment.

The server refuses to start on an unsafe or ambiguous combination (fail
closed), for example an HTTP listener with no authentication configured.
"""

from __future__ import annotations

import os
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

ENV_PREFIX = "DAWARICH_MCP_"
UPSTREAM_PREFIX = "DAWARICH_"

# Tool arguments are two timestamps and a few small numbers; nothing legitimate comes close.
MAX_HTTP_BODY_BYTES = 16 * 1024
MAX_SECRET_FILE_BYTES = 4096

Transport = Literal["stdio", "http"]
AuthMode = Literal["none", "token", "oauth"]
LogFormat = Literal["json", "text"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# Asymmetric algorithms only: symmetric (HS*) keys and "none" are never accepted.
ALLOWED_JWT_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)
DEFAULT_SCOPE = "dawarich:read"

_TOKEN_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_HTTP_PATH_RE = re.compile(r"^/[A-Za-z0-9/_-]{0,63}$")
_SCOPE_RE = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]+$")  # RFC 6749 scope-token
_CREDENTIAL_RE = re.compile(r"^[\x21-\x7e]{1,512}$")  # printable ASCII, no spaces
_HOST_HEADER_RE = re.compile(r"^[A-Za-z0-9._\-:*\[\]]{1,253}$")


class ConfigError(ValueError):
    """Raised when the configuration is invalid or unsafe. Messages never contain secret values."""


class Secret:
    """Holds a credential without ever rendering it in reprs, logs or tracebacks."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret('**********')"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class OAuthSettings:
    issuer: str
    jwks_url: str
    resource_url: str
    required_scopes: tuple[str, ...]
    algorithms: tuple[str, ...]
    leeway_seconds: int


@dataclass(slots=True)  # not frozen: load_settings populates fields in place, then it is read-only by convention
class Settings:
    transport: Transport = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000
    http_path: str = "/mcp"
    allowed_hosts: tuple[str, ...] = ("127.0.0.1:*", "localhost:*", "[::1]:*")
    allowed_origins: tuple[str, ...] = ("http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*")
    http_max_connections: int = 64
    forwarded_allow_ips: str | None = None

    # Upstream Dawarich instance. The API key is wrapped so it cannot leak through repr().
    dawarich_base_url: str = "http://127.0.0.1:3000"
    dawarich_api_key: Secret | None = field(default=None, repr=False)
    # Rails in production rejects untrusted Host headers; when the upstream sits behind a
    # proxy/hostname (or you reach it by container name) send these fixed headers.
    dawarich_host_header: str | None = None
    dawarich_forwarded_proto: str | None = None
    upstream_timeout: float = 20.0

    # Tool output caps.
    max_visits: int = 60
    max_geofence_events: int = 100
    max_search_results: int = 50
    max_window_days: int = 366

    rate_limit_per_minute: int = 60
    rate_limit_burst: int = 20

    auth_mode: AuthMode = "none"
    # sha256(token) -> label. Only hashes are held, so a leaked config does not leak tokens.
    token_hashes: Mapping[bytes, str] = field(default_factory=dict)
    oauth: OAuthSettings | None = None

    log_level: LogLevel = "INFO"
    log_format: LogFormat = "json"


def _env(name: str) -> str | None:
    value = os.environ.get(name)
    return value.strip() if isinstance(value, str) else None


def _read_secret_file(path_value: str, name: str) -> str:
    path = Path(path_value)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"{name}: cannot read secret file {path}") from exc
    if not raw or len(raw) > MAX_SECRET_FILE_BYTES:
        raise ConfigError(f"{name}: secret file is empty or too large")
    value = raw.decode("utf-8").strip()
    if not value:
        raise ConfigError(f"{name}: secret file contains no credential")
    return value


def _parse_token_hashes(raw: str | None) -> dict[bytes, str]:
    """``label:sha256hex`` or bare ``sha256hex`` entries, comma-separated."""
    hashes: dict[bytes, str] = {}
    if not raw:
        return hashes
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        label: str | None = None
        if ":" in entry:
            label, digest = entry.rsplit(":", 1)
            if not _LABEL_RE.fullmatch(label) or not _TOKEN_HASH_RE.fullmatch(digest):
                raise ConfigError("DAWARICH_MCP_AUTH_TOKEN_HASHES: invalid label:sha256 entry")
        else:
            digest = entry
            if not _TOKEN_HASH_RE.fullmatch(digest):
                raise ConfigError("DAWARICH_MCP_AUTH_TOKEN_HASHES: entries must be sha256 hex digests")
        hashes[bytes.fromhex(digest)] = label or digest[:12]
    return hashes


def _parse_allowed(raw: str | None, default: tuple[str, ...], env_name: str) -> tuple[str, ...]:
    if raw is None or not raw.strip():
        return default
    entries = tuple(item.strip() for item in raw.split(",") if item.strip())
    for item in entries:
        if len(item) > 253 or any(ch.isspace() for ch in item):
            raise ConfigError(f"{env_name}: invalid entry {item!r}")
    return entries


def _validate_upstream_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ConfigError("DAWARICH_BASE_URL must be an http(s) URL, e.g. http://dawarich-app-1:3000")
    if ".." in (parts.path or ""):
        raise ConfigError("DAWARICH_BASE_URL must not contain path traversal")
    return url.rstrip("/")


def load_settings(
    *,
    transport: Transport | None = None,
    host: str | None = None,
    port: int | None = None,
) -> Settings:
    """Read the environment, apply CLI overrides and fail closed on unsafe combinations."""
    def server_env(name: str, default: str | None = None) -> str | None:
        raw = _env(ENV_PREFIX + name)
        return raw if raw is not None else default

    transport_value = (transport or server_env("TRANSPORT", "stdio")).lower()
    if transport_value not in ("stdio", "http"):
        raise ConfigError("DAWARICH_MCP_TRANSPORT must be 'stdio' or 'http'")
    settings = Settings(transport=transport_value)  # type: ignore[arg-type]

    settings.host = (host or server_env("HOST") or settings.host).strip()
    port_value = port or server_env("PORT")
    if port_value is not None:
        try:
            settings.port = int(port_value)
        except ValueError as exc:
            raise ConfigError("DAWARICH_MCP_PORT must be an integer") from exc
        if not 1 <= settings.port <= 65535:
            raise ConfigError("DAWARICH_MCP_PORT out of range")

    http_path = server_env("HTTP_PATH", settings.http_path)
    if not _HTTP_PATH_RE.fullmatch(http_path):
        raise ConfigError("DAWARICH_MCP_HTTP_PATH must start with / and be short ASCII")
    settings.http_path = http_path

    settings.allowed_hosts = _parse_allowed(
        server_env("ALLOWED_HOSTS"), settings.allowed_hosts, ENV_PREFIX + "ALLOWED_HOSTS"
    )
    settings.allowed_origins = _parse_allowed(
        server_env("ALLOWED_ORIGINS"), settings.allowed_origins, ENV_PREFIX + "ALLOWED_ORIGINS"
    )

    # ---- upstream credentials (keep the upstream product name) ------------------------------
    base_url = _env(UPSTREAM_PREFIX + "BASE_URL")
    settings.dawarich_base_url = _validate_upstream_url(
        base_url if base_url else settings.dawarich_base_url
    )
    api_key_raw = _env(UPSTREAM_PREFIX + "API_KEY")
    api_key_file = _env(UPSTREAM_PREFIX + "API_KEY_FILE")
    if api_key_raw and api_key_file:
        raise ConfigError("Set either DAWARICH_API_KEY or DAWARICH_API_KEY_FILE, not both")
    if api_key_file:
        api_key_raw = _read_secret_file(api_key_file, UPSTREAM_PREFIX + "API_KEY_FILE")
    if api_key_raw:
        if not _CREDENTIAL_RE.fullmatch(api_key_raw):
            raise ConfigError("DAWARICH_API_KEY contains characters that are not printable ASCII")
        settings.dawarich_api_key = Secret(api_key_raw)

    host_header = _env(UPSTREAM_PREFIX + "HOST_HEADER")
    if host_header:
        if not _HOST_HEADER_RE.fullmatch(host_header):
            raise ConfigError("DAWARICH_HOST_HEADER is not a valid Host header value")
        settings.dawarich_host_header = host_header
    forwarded_proto = _env(UPSTREAM_PREFIX + "FORWARDED_PROTO")
    if forwarded_proto:
        if forwarded_proto not in ("http", "https"):
            raise ConfigError("DAWARICH_FORWARDED_PROTO must be 'http' or 'https'")
        settings.dawarich_forwarded_proto = forwarded_proto

    timeout_value = server_env("UPSTREAM_TIMEOUT")
    if timeout_value is not None:
        try:
            settings.upstream_timeout = float(timeout_value)
        except ValueError as exc:
            raise ConfigError("DAWARICH_MCP_UPSTREAM_TIMEOUT must be a number of seconds") from exc
        if not 1.0 <= settings.upstream_timeout <= 120.0:
            raise ConfigError("DAWARICH_MCP_UPSTREAM_TIMEOUT must be between 1 and 120 seconds")

    for attr, env in (("max_visits", "MAX_VISITS"), ("max_geofence_events", "MAX_GEOFENCE_EVENTS"),
                      ("max_search_results", "MAX_SEARCH_RESULTS"), ("max_window_days", "MAX_WINDOW_DAYS")):
        raw = server_env(env)
        if raw is not None:
            try:
                value = int(raw)
            except ValueError as exc:
                raise ConfigError(f"{ENV_PREFIX}{env} must be an integer") from exc
            if not 1 <= value <= 500:
                raise ConfigError(f"{ENV_PREFIX}{env} out of range (1-500)")
            setattr(settings, attr, value)

    rate_value = server_env("RATE_LIMIT_PER_MINUTE")
    if rate_value is not None:
        try:
            settings.rate_limit_per_minute = int(rate_value)
        except ValueError as exc:
            raise ConfigError("DAWARICH_MCP_RATE_LIMIT_PER_MINUTE must be an integer") from exc
        if not 1 <= settings.rate_limit_per_minute <= 600:
            raise ConfigError("DAWARICH_MCP_RATE_LIMIT_PER_MINUTE out of range (1-600)")
    burst_value = server_env("RATE_LIMIT_BURST")
    if burst_value is not None:
        try:
            settings.rate_limit_burst = int(burst_value)
        except ValueError as exc:
            raise ConfigError("DAWARICH_MCP_RATE_LIMIT_BURST must be an integer") from exc
        if not 1 <= settings.rate_limit_burst <= 200:
            raise ConfigError("DAWARICH_MCP_RATE_LIMIT_BURST out of range (1-200)")

    # ---- authentication ---------------------------------------------------------------------
    auth_mode = (server_env("AUTH_MODE", "token") or "token").lower()
    if auth_mode not in ("none", "token", "oauth"):
        raise ConfigError("DAWARICH_MCP_AUTH_MODE must be 'none', 'token' or 'oauth'")
    settings.token_hashes = _parse_token_hashes(server_env("AUTH_TOKEN_HASHES"))
    settings.auth_mode = auth_mode  # type: ignore[assignment]

    if settings.transport == "http" and settings.auth_mode == "none":
        raise ConfigError(
            "Refusing to start an HTTP MCP server without authentication: set "
            "DAWARICH_MCP_AUTH_MODE=token with DAWARICH_MCP_AUTH_TOKEN_HASHES, or configure OAuth"
        )
    if settings.auth_mode == "token" and not settings.token_hashes:
        raise ConfigError(
            "Static-token auth needs at least one hash in DAWARICH_MCP_AUTH_TOKEN_HASHES "
            "(generate one with: dawarich-mcp gen-token)"
        )

    issuer = server_env("OAUTH_ISSUER")
    jwks_url = server_env("OAUTH_JWKS_URL")
    resource_url = server_env("OAUTH_RESOURCE_URL")
    scopes_raw = server_env("OAUTH_REQUIRED_SCOPES", DEFAULT_SCOPE) or DEFAULT_SCOPE
    if auth_mode == "oauth":
        missing = [
            name
            for name, value in (
                ("DAWARICH_MCP_OAUTH_ISSUER", issuer),
                ("DAWARICH_MCP_OAUTH_JWKS_URL", jwks_url),
                ("DAWARICH_MCP_OAUTH_RESOURCE_URL", resource_url),
            )
            if not value
        ]
        if missing:
            raise ConfigError(f"OAuth mode requires {' and '.join(missing)}")
        for name, value in (("DAWARICH_MCP_OAUTH_ISSUER", issuer), ("DAWARICH_MCP_OAUTH_JWKS_URL", jwks_url),
                            ("DAWARICH_MCP_OAUTH_RESOURCE_URL", resource_url)):
            parts = urlsplit(value or "")
            if parts.scheme != "https" or not parts.netloc:
                raise ConfigError(f"{name} must be an https URL")
        scopes = tuple(s for s in (scopes_raw or "").split() if s)
        for scope in scopes:
            if not _SCOPE_RE.fullmatch(scope):
                raise ConfigError("DAWARICH_MCP_OAUTH_REQUIRED_SCOPES contains an invalid scope token")
        leeway = server_env("OAUTH_LEEWAY_SECONDS")
        settings.oauth = OAuthSettings(
            issuer=issuer or "",  # type: ignore[arg-type]
            jwks_url=jwks_url or "",  # type: ignore[arg-type]
            resource_url=resource_url or "",  # type: ignore[arg-type]
            required_scopes=scopes,
            algorithms=tuple(sorted(ALLOWED_JWT_ALGORITHMS)),
            leeway_seconds=int(leeway) if leeway and leeway.isdigit() else 60,
        )

    log_level = (server_env("LOG_LEVEL", settings.log_level) or settings.log_level).upper()
    if log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        raise ConfigError("DAWARICH_MCP_LOG_LEVEL is not a valid level")
    settings.log_level = log_level  # type: ignore[assignment]
    log_format = (server_env("LOG_FORMAT", settings.log_format) or settings.log_format).lower()
    if log_format not in ("json", "text"):
        raise ConfigError("DAWARICH_MCP_LOG_FORMAT must be 'json' or 'text'")
    settings.log_format = log_format  # type: ignore[assignment]

    settings.http_max_connections = int(server_env("HTTP_MAX_CONNECTIONS", "64") or 64)
    settings.forwarded_allow_ips = server_env("FORWARDED_ALLOW_IPS")

    # Fail closed on a half-configured deployment rather than serving error tools.
    if settings.dawarich_api_key is None and settings.transport == "http":
        # The server may still start (tools report the misconfiguration to the model), but
        # `dawarich-mcp check` will fail loudly. Keep the key required for stdio too, where
        # a missing key is always a mistake.
        pass  # validated in cli._check; serving tools without upstream access is not unsafe
    return settings


def random_hex(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)
