"""Shared fixtures. Tests import the package straight from src/ without installing."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from dawarich_mcp.auth import generate_token
from dawarich_mcp.config import Settings


@pytest.fixture()
def settings() -> Settings:
    _token, digest = generate_token()
    return Settings(
        transport="stdio",
        dawarich_base_url="http://dawarich.test:3000",
        dawarich_api_key=None,
        auth_mode="token",
        token_hashes={bytes.fromhex(digest): "test"},
    )
