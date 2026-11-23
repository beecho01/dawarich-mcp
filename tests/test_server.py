"""Server tools against a stubbed DawarichAPI: happy paths and guardrails."""

from __future__ import annotations

import anyio
import pytest

from dawarich_mcp.config import Settings
from dawarich_mcp.dawarich import DawarichAPI
from dawarich_mcp.server import ToolGuard  # noqa: F401  (guard exercised through tools)


class StubAPI(DawarichAPI):
    def __init__(self) -> None:
        Settings()  # no client needed; all methods are overridden

    async def health(self):
        return {"status": "ok"}

    async def me(self):
        return {
            "email": "user@example.com",
            "settings": {"timezone": "Europe/London", "maps": {"distance_unit": "mi"}},
        }

    async def tracked_months(self):
        return [{"year": 2025, "months": ["Oct", "Nov", "Dec"]}]

    async def latest_points(self, count: int = 1):
        return [
            {
                "timestamp": 1765407202,
                "latitude": 53.05,
                "longitude": -0.76,
                "altitude": 71,
                "accuracy": 55,
                "city": None,
                "country": None,
                "tracker_id": "Dawarich",
            }
        ]

    async def visits(self, start_iso, end_iso, *, page, per_page):
        return [
            {
                "started_at": "2025-11-20T09:00:00Z",
                "ended_at": "2025-11-20T17:30:00Z",
                "name": "Home \x1b[31mEVIL\u202e",
                "latitude": 53.05,
                "longitude": -0.76,
                "city": "Newark-on-Trent",
                "country": "United Kingdom",
            }
        ]

    async def stats(self):
        return {
            "totalDistanceKm": 1066,
            "totalPointsTracked": 7328,
            "yearlyStats": [
                {
                    "year": 2025,
                    "totalDistanceKm": 1066,
                    "totalCountriesVisited": 0,
                    "totalCitiesVisited": 0,
                    "monthlyDistanceKm": {"november": 687},
                }
            ],
        }

    async def insights(self, year: int):
        return {
            "year": year,
            "availableYears": [2025],
            "totals": {"totalDistance": 0, "distanceUnit": "mi", "countriesCount": 0, "citiesCount": 0, "daysTraveling": 0},
        }

    async def digest_list(self):
        return {"digests": [{"year": 2025, "distance": 1066676, "countriesCount": 0, "citiesCount": 0, "createdAt": "2026-02-01T01:33:07+00:00"}]}

    async def digest(self, year: int):
        return {"distance": 1066676, "countriesCount": 0, "citiesCount": 0}

    async def geofence_events(self, start_epoch, end_epoch, *, place_id=None, page, per_page):
        return []

    async def countries_visited(self, start_epoch, end_epoch):
        return [{"country": "United Kingdom"}]

    async def visited_cities(self, start_epoch, end_epoch):
        return [{"city": "Newark-on-Trent"}, {"city": "Madrid"}]


def _build():
    from dawarich_mcp.config import Settings
    from dawarich_mcp.server import build_server

    settings = Settings(transport="stdio")
    return build_server(settings, api=StubAPI())


def _call(mcp, name, args):
    async def run():
        return await mcp.call_tool(name, args)

    return anyio.run(run)


def test_tools_registered() -> None:
    mcp = _build()

    async def run():
        return await mcp.list_tools()

    tools = anyio.run(run)
    names = {t.name for t in tools}
    assert names == {
        "dawarich_status",
        "dawarich_latest_location",
        "dawarich_where_was_i",
        "dawarich_distance_stats",
        "dawarich_year_insights",
        "dawarich_year_digest",
        "dawarich_geofence_events",
        "dawarich_visited_places",
    }
    for tool in tools:
        assert tool.annotations is not None and tool.annotations.read_only_hint is True


def test_status_reports_tracked_months() -> None:
    mcp = _build()
    result = _call(mcp, "dawarich_status", {})
    assert result.structured_content["dawarich_healthy"] is True
    assert result.structured_content["user_email"] == "user@example.com"
    assert result.structured_content["tracked_months"][0]["year"] == 2025


def test_where_was_i_sanitises_and_counts_duration() -> None:
    mcp = _build()
    result = _call(mcp, "dawarich_where_was_i", {"start": "2025-11-20", "end": "2025-11-21"})
    visit = result.structured_content["visits"][0]
    assert "\x1b" not in visit["name"] and "\u202e" not in visit["name"]
    assert visit["duration_minutes"] == 510.0
    assert result.structured_content["total_returned"] == 1


def test_where_was_i_rejects_inverted_range() -> None:
    mcp = _build()
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError, match="not be earlier"):
        _call(mcp, "dawarich_where_was_i", {"start": "2025-11-21", "end": "2025-11-20"})


def test_distance_stats_months() -> None:
    mcp = _build()
    result = _call(mcp, "dawarich_distance_stats", {})
    assert result.structured_content["total_distance_km"] == 1066
    assert result.structured_content["years"][0]["monthly"][0]["month"] == "november"


def test_digest_missing_year_is_user_facing_error() -> None:
    mcp = _build()
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError, match="Dawarich web UI"):
        _call(mcp, "dawarich_year_digest", {"year": 2031})


def test_visited_places_labels() -> None:
    mcp = _build()
    result = _call(mcp, "dawarich_visited_places", {"start": "2025-01-01", "end": "2025-12-31"})
    assert "Madrid" in result.structured_content["cities"]
    assert "United Kingdom" in result.structured_content["countries"]


def test_latest_location_epoch_to_iso() -> None:
    mcp = _build()
    result = _call(mcp, "dawarich_latest_location", {})
    assert result.structured_content["point"]["timestamp"].startswith("2025-12")
    assert result.structured_content["point"]["latitude"] == 53.05
