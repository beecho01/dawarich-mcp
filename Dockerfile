# syntax=docker/dockerfile:1.7
#
# dawarich-mcp: hardened read-only MCP server for a self-hosted Dawarich instance.
# Published to ghcr.io/beecho01/dawarich-mcp by .github/workflows/docker-publish.yml.
#
# Base images are pinned by tag (uv, python). Add (multi-arch index) digests for extra
# reproducibility; Dependabot (.github/dependabot.yml) proposes updates to the FROM lines.

FROM ghcr.io/astral-sh/uv:0.13.6 AS uv
FROM python:3.15-slim-trixie AS python

# ---- build: resolve exactly what uv.lock pins (hash-checked) into a venv -------------------------
FROM python AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src

# Dependencies first (better layer caching), then the project itself.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project
COPY README.md LICENSE ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

# ---- runtime: no build tools, no pip, non-root ----------------------------------------------------
FROM python AS runtime

LABEL org.opencontainers.image.title="dawarich-mcp" \
      org.opencontainers.image.description="Hardened read-only MCP server for a self-hosted Dawarich instance" \
      org.opencontainers.image.licenses="MIT"

# Nothing installs packages at runtime, so remove pip; create an unprivileged user with no shell or home.
RUN python -m pip uninstall --yes --root-user-action=ignore pip \
 && groupadd --system --gid 10001 mcp \
 && useradd --system --uid 10001 --gid mcp --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin mcp

COPY --from=builder /opt/venv /opt/venv

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONSAFEPATH=1 \
    DAWARICH_MCP_HOST=0.0.0.0 \
    DAWARICH_MCP_PORT=8000

USER 10001:10001
WORKDIR /
EXPOSE 8000

ENTRYPOINT ["dawarich-mcp"]
# HTTP by default; it refuses to start until authentication is configured.
# For stdio: docker run -i --rm ... dawarich-mcp serve --transport stdio
CMD ["serve", "--transport", "http"]
