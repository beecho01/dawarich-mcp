"""Command-line entry point: ``dawarich-mcp [serve|gen-token|check|healthcheck]``.

With no arguments it serves MCP over stdio, so client configurations like
``uvx dawarich-mcp`` keep working.
"""

from __future__ import annotations

import argparse
import logging
import sys
import urllib.error
import urllib.request

import anyio

from dawarich_mcp import __version__
from dawarich_mcp.auth import generate_token
from dawarich_mcp.config import ConfigError, load_settings
from dawarich_mcp.logs import configure_logging

logger = logging.getLogger("dawarich_mcp")


def _serve(args: argparse.Namespace) -> int:
    try:
        settings = load_settings(transport=args.transport, host=args.host, port=args.port)
    except ConfigError as exc:
        print(f"dawarich-mcp: configuration error: {exc}", file=sys.stderr)
        return 2
    configure_logging(settings.log_level, settings.log_format)

    from dawarich_mcp.server import build_server  # imported late so config errors print fast

    mcp = build_server(settings)
    logger.info(
        "dawarich-mcp %s starting",
        __version__,
        extra={"event": {"transport": settings.transport}},
    )
    if settings.transport == "stdio":
        anyio.run(mcp.run_stdio_async)
    else:
        from dawarich_mcp.http import run_http

        run_http(settings, mcp)
    return 0


def _gen_token(args: argparse.Namespace) -> int:
    token, digest = generate_token()
    label = args.label
    print("Give this bearer token to the MCP client (shown once, store it in a secret manager):")
    print(f"  {token}")
    print()
    print("Add this entry to DAWARICH_MCP_AUTH_TOKEN_HASHES (comma-separated) on the server:")
    print(f"  {label}:{digest}" if label else f"  {digest}")
    return 0


def _check(_: argparse.Namespace) -> int:
    """Verify the upstream configuration end to end: base URL, API key, and a real read."""
    try:
        settings = load_settings(transport="stdio", host=None, port=None)
    except ConfigError as exc:
        print(f"dawarich-mcp: configuration error: {exc}", file=sys.stderr)
        return 2
    if settings.dawarich_api_key is None:
        print("dawarich-mcp: DAWARICH_API_KEY (or _FILE) is not set", file=sys.stderr)
        return 2

    from dawarich_mcp import dawarich as dw

    async def run() -> tuple[bool, str]:
        try:
            client = dw.new_client(settings)
        except dw.UpstreamError as exc:
            return False, str(exc)
        try:
            status, payload = await dw.request_json(
                client,
                "GET",
                settings.dawarich_base_url + "/api/v1/health",
                service="Dawarich",
                headers={"Accept": "application/json"},
            )
            if status != 200:
                return False, f"Dawarich /api/v1/health answered HTTP {status}"
            status, payload = await dw.request_json(
                client,
                "GET",
                settings.dawarich_base_url + "/api/v1/users/me",
                service="Dawarich",
                headers={"Accept": "application/json"},
            )
            if status == 401:
                return False, "Dawarich rejected the API key (401) — check DAWARICH_API_KEY"
            if status != 200:
                return False, f"Dawarich /api/v1/users/me answered HTTP {status}"
            email = (payload.get("user") or {}).get("email", "unknown")
            return True, f"credentials accepted for {email}"
        finally:
            await client.aclose()

    ok, message = anyio.run(run)
    print(("PASS " if ok else "FAIL ") + message)
    return 0 if ok else 1


def _healthcheck(_: argparse.Namespace) -> int:
    """For the Docker HEALTHCHECK: 200 from /healthz, no auth required."""
    try:
        settings = load_settings(transport="http")
    except ConfigError:
        return 1
    url = f"http://127.0.0.1:{settings.port}/healthz"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return 0 if response.status == 200 else 1
    except (urllib.error.URLError, OSError, ValueError):
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dawarich-mcp",
        description="Hardened read-only MCP server for a self-hosted Dawarich instance",
    )
    parser.add_argument("--version", action="version", version=f"dawarich-mcp {__version__}")
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="serve MCP (default: stdio)")
    serve.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    serve.add_argument("--host", default=None, help="bind host for http (default 127.0.0.1)")
    serve.add_argument("--port", type=int, default=None, help="bind port for http (default 8000)")
    serve.set_defaults(func=_serve)

    gen_token = sub.add_parser("gen-token", help="generate a bearer token and its sha256 hash")
    gen_token.add_argument("--label", default="", help="optional label for the token, e.g. openwebui")
    gen_token.set_defaults(func=_gen_token)

    check = sub.add_parser("check", help="verify the upstream Dawarich configuration end to end")
    check.set_defaults(func=_check)

    healthcheck = sub.add_parser("healthcheck", help="for the Docker HEALTHCHECK: GET /healthz")
    healthcheck.set_defaults(func=_healthcheck)

    # No subcommand at all -> serve over stdio, so `uvx dawarich-mcp` keeps working.
    argv = list(sys.argv[1:] if argv is None else argv) or ["serve"]
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
