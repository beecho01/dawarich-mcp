"""Shared plumbing for outbound HTTP calls to the Dawarich API.

* Only the fixed, operator-configured base URL is contacted. No URL, host or
  path segment is taken from tool arguments; query parameters are strictly
  validated and bounded.
* Redirects are never followed, so the API key cannot be bounced to another host.
* Response bodies are read as a stream and capped (after decompression), so a
  misbehaving or compromised upstream cannot exhaust memory.
* The Dawarich API key is sent as ``Authorization: Bearer`` only, exactly the
  way Dawarich's own API authenticates (it ignores ``X-Api-Key`` and query
  parameters since v1.23), and is never exposed through tool results.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import httpx2

from dawarich_mcp import __version__
from dawarich_mcp.config import Settings

USER_AGENT = f"dawarich-mcp/{__version__}"

# Responses above this are refused before parsing. A single page of visits or
# points is a few hundred KB at most; anything larger is a runaway query.
MAX_PAGE_BYTES = 8 * 1024 * 1024


class UserFacingError(Exception):
    """An error whose message is safe to show to the MCP client and the model.

    Messages never contain credentials, tokens, internal hostnames or raw upstream bodies.
    """


class InvalidInputError(UserFacingError):
    """The tool arguments were well-formed JSON but not usable (bad date, inverted range...)."""


class UpstreamError(UserFacingError):
    """The Dawarich API failed, refused us, or returned something unusable."""


ISO_INPUT_RE_OK_CHARS = set("0123456789TZtz:+-. ")


def parse_iso(value: str) -> datetime:
    """Parse a strict ISO 8601 date or datetime (the only format tools accept)."""
    text = value.strip()
    if not text or any(ch not in ISO_INPUT_RE_OK_CHARS for ch in text):
        raise InvalidInputError("Dates must be ISO 8601, e.g. 2026-11-23 or 2026-11-23T09:30:00Z")
    try:
        if "T" in text or " " in text:
            iso = text.replace(" ", "T")
            if iso.endswith(("Z", "z")):
                iso = iso[:-1] + "+00:00"
            parsed = datetime.fromisoformat(iso)
        else:
            parsed = datetime.fromisoformat(text + "T00:00:00+00:00")
    except ValueError as exc:
        raise InvalidInputError(f"Could not read the date {value!r} as ISO 8601") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def to_epoch(value: str) -> int:
    return int(parse_iso(value).timestamp())


def new_client(settings: Settings, transport: httpx2.AsyncBaseTransport | None = None) -> httpx2.AsyncClient:
    if settings.dawarich_api_key is None:
        raise UpstreamError(
            "No Dawarich API key is configured on the server (DAWARICH_API_KEY / _FILE); "
            "tools cannot query location history."
        )
    headers: dict[str, str] = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "Authorization": "Bearer " + settings.dawarich_api_key.reveal(),
    }
    # Rails in production rejects untrusted Host headers; honour the operator's
    # proxy hostname instead of the container-internal one.
    if settings.dawarich_host_header:
        headers["Host"] = settings.dawarich_host_header
    if settings.dawarich_forwarded_proto:
        headers["X-Forwarded-Proto"] = settings.dawarich_forwarded_proto
    return httpx2.AsyncClient(
        transport=transport,
        timeout=httpx2.Timeout(settings.upstream_timeout, connect=10.0),
        follow_redirects=False,
        headers=headers,
        limits=httpx2.Limits(max_connections=8, max_keepalive_connections=4),
    )


async def request_json(
    client: httpx2.AsyncClient,
    method: str,
    url: str,
    *,
    service: str,
    **kwargs: Any,
) -> tuple[int, Any]:
    """Send a request and return ``(status, parsed JSON)``.

    The body is only read (and parsed) for 200 responses; for any other status the
    parsed value is None. Raises ``UpstreamError`` if the body exceeds the cap
    or is not valid JSON.
    """
    async with client.stream(method, url, **kwargs) as response:
        status = response.status_code
        if status != 200:
            return status, None
        declared = response.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_PAGE_BYTES:
            raise UpstreamError(f"{service} sent an unexpectedly large response; refusing to read it.")
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body += chunk
            if len(body) > MAX_PAGE_BYTES:
                raise UpstreamError(f"{service} sent an unexpectedly large response; refusing to read it.")
    try:
        return status, json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise UpstreamError(f"{service} returned a response that is not valid JSON.") from exc


class DawarichAPI:
    """Typed, bounded calls against the Dawarich REST API v1 (read-only).

    ``client`` may be None when no API key is configured; every call then raises
    a ``UpstreamError`` whose message tells the operator how to fix it, instead of
    the server crashing at startup.
    """

    _NO_KEY_MESSAGE = (
        "No Dawarich API key is configured on the server (DAWARICH_API_KEY / _FILE); "
        "tools cannot query location history."
    )

    def __init__(self, settings: Settings, client: httpx2.AsyncClient | None) -> None:
        self._settings = settings
        self._client = client

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        if self._client is None:
            raise UpstreamError(self._NO_KEY_MESSAGE)
        status, payload = await request_json(
            self._client, "GET", self._settings.dawarich_base_url + path, params=params, service="Dawarich"
        )
        if status == 401:
            raise UpstreamError("Dawarich rejected the configured API key (401).")
        if status == 404:
            raise UpstreamError(f"Dawarich has no endpoint at {path} (404) — check the Dawarich version.")
        if status == 422 or status == 400:
            raise UpstreamError(f"Dawarich refused the request ({status}); the arguments may not be valid for this version.")
        if status != 200:
            raise UpstreamError(f"Dawarich answered HTTP {status}.")
        return payload

    async def health(self) -> dict[str, Any]:
        payload = await self._get("/api/v1/health")
        return payload if isinstance(payload, dict) else {}

    async def me(self) -> dict[str, Any]:
        payload = await self._get("/api/v1/users/me")
        user = payload.get("user") if isinstance(payload, dict) else None
        return user if isinstance(user, dict) else {}

    async def tracked_months(self) -> list[dict[str, Any]]:
        payload = await self._get("/api/v1/points/tracked_months")
        return payload if isinstance(payload, list) else []

    async def latest_points(self, count: int = 1) -> list[dict[str, Any]]:
        payload = await self._get(
            "/api/v1/points", {"order": "desc", "per_page": min(count, 5), "page": 1}
        )
        return payload if isinstance(payload, list) else []

    async def visits(self, start_iso: str, end_iso: str, *, page: int, per_page: int) -> list[dict[str, Any]]:
        payload = await self._get(
            "/api/v1/visits",
            {"start_at": start_iso, "end_at": end_iso, "page": page, "per_page": min(per_page, 200)},
        )
        return payload if isinstance(payload, list) else []

    async def stats(self) -> dict[str, Any]:
        payload = await self._get("/api/v1/stats")
        return payload if isinstance(payload, dict) else {}

    async def insights(self, year: int) -> dict[str, Any]:
        payload = await self._get("/api/v1/insights", {"year": year})
        return payload if isinstance(payload, dict) else {}

    async def digest_list(self) -> dict[str, Any]:
        payload = await self._get("/api/v1/digests")
        return payload if isinstance(payload, dict) else {}

    async def digest(self, year: int) -> dict[str, Any]:
        payload = await self._get(f"/api/v1/digests/{year}")
        return payload if isinstance(payload, dict) else {}

    async def geofence_events(
        self, start_epoch: int, end_epoch: int, *, place_id: str | None = None, page: int, per_page: int
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {
            "start_at": start_epoch,
            "end_at": end_epoch,
            "page": page,
            "per_page": min(per_page, 200),
        }
        if place_id:
            params["place_id"] = place_id
        payload = await self._get("/api/v1/geofence_events", params)
        return payload if isinstance(payload, list) else []

    async def countries_visited(self, start_epoch: int, end_epoch: int) -> list[dict[str, Any]]:
        payload = await self._get(
            "/api/v1/countries/visited", {"start_at": start_epoch, "end_at": end_epoch}
        )
        return payload if isinstance(payload, list) else []

    async def visited_cities(self, start_epoch: int, end_epoch: int) -> list[dict[str, Any]]:
        payload = await self._get(
            "/api/v1/countries/visited_cities", {"start_at": start_epoch, "end_at": end_epoch}
        )
        return payload if isinstance(payload, list) else []
