"""End-to-end check of a running deployment: auth, transport protections and real tool calls.

    MCP_URL=http://127.0.0.1:8000/mcp MCP_TOKEN=dwmcp_... uv run scripts/smoke_test.py

Exits non-zero on the first failed expectation. Live-data checks run only when the
server has a Dawarich API key configured, so this also works in CI without secrets.
"""

from __future__ import annotations

import asyncio
import os
import sys

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

EXPECTED_TOOLS = {
    "dawarich_status",
    "dawarich_latest_location",
    "dawarich_where_was_i",
    "dawarich_distance_stats",
    "dawarich_year_insights",
    "dawarich_year_digest",
    "dawarich_geofence_events",
    "dawarich_visited_places",
}


def check(condition: bool, label: str) -> None:
    print(("PASS " if condition else "FAIL ") + label)
    if not condition:
        sys.exit(1)


async def main() -> None:
    url = os.environ.get("MCP_URL", "http://127.0.0.1:8000/mcp")
    token = os.environ["MCP_TOKEN"]
    json_headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    probe = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

    async with httpx2.AsyncClient(timeout=30) as raw:
        health = await raw.get(url.rsplit("/", 1)[0] + "/healthz")
        check(health.status_code == 200, "/healthz answers without authentication")
        response = await raw.post(url, content=probe, headers=json_headers)
        check(response.status_code == 401, "request without a token is rejected (401)")
        response = await raw.post(
            url, content=probe, headers={**json_headers, "Authorization": "Bearer dwmcp_nope"}
        )
        check(response.status_code == 401, "request with a wrong token is rejected (401)")
        response = await raw.post(
            url,
            content=probe,
            headers={**json_headers, "Authorization": f"Bearer {token}", "Origin": "https://evil.example"},
        )
        check(response.status_code == 403, "cross-site Origin is rejected (403, DNS-rebinding protection)")
        response = await raw.get(url, headers={"Authorization": f"Bearer {token}"})
        check(response.status_code == 405, "GET on the MCP endpoint is refused (405, no session streams)")

    for mode in ("auto", "legacy"):
        async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=120) as http:
            async with Client(streamable_http_client(url, http_client=http), mode=mode) as client:  # type: ignore[arg-type]
                label = f"[{mode}, protocol {client.protocol_version}]"
                tools = {tool.name for tool in (await client.list_tools()).tools}
                check(tools == EXPECTED_TOOLS, f"{label} tools listed: {sorted(tools)}")

                status = (await client.call_tool("dawarich_status", {})).structured_content
                check(isinstance(status["dawarich_healthy"], bool), f"{label} status call succeeded")

                bad = await client.call_tool("dawarich_where_was_i", {"start": "2026-11-23", "end": "2026-11-01"})
                check(bool(bad.is_error), f"{label} inverted range is a tool error, not a crash")
                nonsense = await client.call_tool("dawarich_where_was_i", {"start": "Narnia", "end": "Oz"})
                check(bool(nonsense.is_error), f"{label} non-ISO dates are rejected by the schema")

                if not status.get("api_key_valid"):
                    print(f"SKIP {label} live-data checks (no Dawarich API key on the server)")
                    continue
                result = await client.call_tool("dawarich_distance_stats", {})
                check(not result.is_error, f"{label} live distance stats succeeded")


if __name__ == "__main__":
    asyncio.run(main())
