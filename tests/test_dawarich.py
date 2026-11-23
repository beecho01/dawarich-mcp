"""Timestamp parsing, epoch conversion and upstream error mapping."""

from __future__ import annotations

import json

import httpx2
import pytest

from dawarich_mcp import dawarich as dw
from dawarich_mcp.config import Secret, Settings
from dawarich_mcp.dawarich import DawarichAPI, parse_iso, to_epoch


class _Settings(Settings):
    """Concrete settings for client tests."""


def _settings() -> Settings:
    return Settings(
        dawarich_base_url="http://dawarich.test:3000",
        dawarich_api_key=Secret("test-key"),
    )


def test_parse_iso_date_and_datetime() -> None:
    assert parse_iso("2026-11-23").year == 2026
    assert parse_iso("2026-11-23T09:30:00Z").hour == 9
    assert parse_iso("2026-11-23 09:30:00+00:00").minute == 30


@pytest.mark.parametrize("bad", ["15th of November", "2026-13-45", "", "2026-11-23T09:30Z DROP TABLE"])
def test_parse_iso_rejects_non_iso(bad: str) -> None:
    with pytest.raises(dw.InvalidInputError):
        parse_iso(bad)


def test_to_epoch() -> None:
    assert to_epoch("1970-01-01T00:00:00Z") == 0


def _api(responder) -> DawarichAPI:
    settings = _settings()
    transport = httpx2.MockTransport(responder)
    client = dw.new_client(settings, transport=transport)
    return DawarichAPI(settings, client)


def test_api_maps_401_to_upstream_error() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(401)

    api = _api(handler)
    with pytest.raises(dw.UpstreamError, match="rejected the configured API key"):
        anyio_run(api.health())


def test_api_passes_bearer_and_parses_json() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen["auth"] = request.headers.get("Authorization", "")
        seen["path"] = request.url.path
        return httpx2.Response(200, content=json.dumps({"status": "ok"}).encode())

    api = _api(handler)
    payload = anyio_run(api.health())
    assert payload == {"status": "ok"}
    assert seen["auth"] == "Bearer test-key"
    assert seen["path"] == "/api/v1/health"


def test_api_without_key_reports_configuration() -> None:
    api = DawarichAPI(Settings(), None)
    with pytest.raises(dw.UpstreamError, match="No Dawarich API key"):
        anyio_run(api.stats())


def anyio_run(coro):
    import anyio

    return anyio.run(lambda: coro)
