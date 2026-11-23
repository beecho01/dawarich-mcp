# dawarich-mcp

[![CI](https://github.com/beecho01/dawarich-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/beecho01/dawarich-mcp/actions/workflows/test.yml)
[![Docker](https://github.com/beecho01/dawarich-mcp/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/beecho01/dawarich-mcp/pkgs/container/dawarich-mcp)](https://github.com/beecho01/dawarich-mcp/pkgs/container/dawarich-mcp)

**Hardened, read-only MCP server for a self-hosted [Dawarich](https://dawarich.com) instance.**

Ask an MCP client (Open WebUI, Claude Desktop, etc.) about your location history:
*"where was I on the 15th?"*, *"how far did I travel in November?"*,
*"summarise my 2025"*, *"when did I get home last Friday?"*.

Dawarich v1.23+ ships its own native MCP endpoint with three tools
(`get_timeline`, `get_latest_location`, `search_visits`). This project wraps
Dawarich's **REST API** instead, giving a wider read surface and an
independent, hardened security perimeter around it — see
[Comparison with the native endpoint](#comparison-with-the-native-endpoint).

## Tools (all read-only)

| Tool | Answers |
|---|---|
| `dawarich_status` | Is Dawarich healthy, is the API key accepted, which years/months of history exist? |
| `dawarich_latest_location` | The most recent recorded GPS point |
| `dawarich_where_was_i` | Visits between two ISO 8601 datetimes (≤ 1 year), optional text filter |
| `dawarich_distance_stats` | Distance travelled per year and per month, total points tracked |
| `dawarich_year_insights` | Dawarich's yearly summary for one year |
| `dawarich_year_digest` | A generated year-in-review digest (if created in the Dawarich UI) |
| `dawarich_geofence_events` | Arrivals/departures at configured places in a window |
| `dawarich_visited_places` | Countries and cities visited in a window |

## Quick start

```bash
git clone https://github.com/beecho01/dawarich-mcp && cd dawarich-mcp
mkdir -p secrets
printf '%s' 'YOUR-DAWARICH-API-KEY' > secrets/dawarich_api_key   # Dawarich → Settings → API key
cp .env.example .env
docker compose run --rm --no-deps mcp gen-token --label openwebui   # add the hash to .env
docker compose up -d --build
docker compose run --rm --no-deps mcp check   # verifies base URL + key end to end
```

The example compose does not publish any host port — OpenWebUI reaches the
server container-to-container. To expose it to other clients, publish on
loopback (`127.0.0.1:8000:8000`) and put a TLS-terminating reverse proxy in front.

### Open WebUI

Add the server under Admin → Settings → Tools (or in `TOOL_SERVER_CONNECTIONS`
if you configure via environment):

| | |
|---|---|
| Type | Streamable HTTP |
| URL | `http://dawarich-mcp:8000/mcp` |
| Auth | Bearer token (the `dwmcp_…` value from `gen-token`) |

If OpenWebUI connects by container name, keep `DAWARICH_MCP_ALLOWED_HOSTS`
including `dawarich-mcp:*` (the DNS-rebinding guard rejects unknown hosts).

## Configuration

| Variable | Meaning |
|---|---|
| `DAWARICH_BASE_URL` | Dawarich base URL, e.g. `http://dawarich-app-1:3000` |
| `DAWARICH_API_KEY` / `DAWARICH_API_KEY_FILE` | Dawarich API key (prefer the `_FILE` Docker secret) |
| `DAWARICH_HOST_HEADER` | Host header for the upstream (Rails production rejects untrusted Hosts) |
| `DAWARICH_FORWARDED_PROTO` | `https` if Dawarich sits behind a TLS proxy |
| `DAWARICH_MCP_AUTH_TOKEN_HASHES` | `label:sha256hex` bearer-token hashes |
| `DAWARICH_MCP_OAUTH_*` | OAuth 2.1 resource-server mode (issuer, JWKS URL, resource URL, scopes) |
| `DAWARICH_MCP_ALLOWED_HOSTS` / `_ORIGINS` | DNS-rebinding allowlists for the MCP endpoint |
| `DAWARICH_MCP_RATE_LIMIT_PER_MINUTE` | Per-principal token bucket (default 60) |

`dawarich-mcp check` validates the upstream configuration end to end;
`dawarich-mcp healthcheck` is the container healthcheck.

## Security

Read the [security policy](SECURITY.md) for the full model. Highlights,
following the [MCP security best practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
and [awesome-mcp-security](https://github.com/Puliczek/awesome-mcp-security):

- Fail-closed auth: static bearer tokens are stored as **SHA-256 hashes**;
  OAuth 2.1 resource-server mode validates JWT audience (RFC 8707).
- **No token passthrough** — client tokens never travel upstream.
- DNS-rebinding protection always on; stateless **2026-07-28** streamable HTTP,
  POST-only (GET → 405, no idle streams, no sessions).
- Strict input schemas, bounded windows/counts, sanitised outputs (ANSI,
  control characters, bidi overrides and zero-width characters are stripped).
- Static tool list — no runtime tool swapping (no rug-pull surface).
- Rate limiting, PII-free JSON audit logs, hardened container (read-only FS,
  `cap_drop: ALL`, non-root, no pip, security headers).

## Comparison with the native endpoint

Dawarich (v1.23+, Pro API key required) exposes `/api/v1/mcp` with
`get_timeline`, `get_latest_location` and `search_visits` — genuinely nice
tools with bounded ranges. Differences:

| | Native `/api/v1/mcp` | dawarich-mcp |
|---|---|---|
| Tools | 3 | 8 (status, stats, insights, digests, geofence, countries, …) |
| Auth | Dawarich API key (Bearer) | Own token layer; Dawarich key stays in a Docker secret |
| DNS-rebinding protection | Disabled upstream (`dns_rebinding_protection: false`) | Always on |
| Exposure | The full Rails app | One minimal, read-only-hardened container |
| Rate limiting / output sanitisation | — | Yes |

Use both if you like; they are independent. Contributions of further tools
upstream to Dawarich's native MCP are very welcome.

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
MCP_URL=http://127.0.0.1:8000/mcp MCP_TOKEN=dwmcp_... uv run scripts/smoke_test.py
```

MIT licensed. Dawarich is a project by [Freika](https://github.com/Freika/dawarich).
