"""Config validation: the server fails closed on unsafe combinations."""

from __future__ import annotations

import os

import pytest

from dawarich_mcp.auth import generate_token
from dawarich_mcp.config import ConfigError, load_settings


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith(("DAWARICH_MCP_", "DAWARICH_")):
            monkeypatch.delenv(key, raising=False)


def test_http_without_auth_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("DAWARICH_MCP_TRANSPORT", "http")
    monkeypatch.setenv("DAWARICH_MCP_AUTH_MODE", "none")
    with pytest.raises(ConfigError, match="without authentication"):
        load_settings(transport="http")


def test_http_defaults_to_token_mode_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    # No auth env at all: default token mode refuses to start without a hash.
    with pytest.raises(ConfigError, match="gen-token"):
        load_settings(transport="http")


def test_token_mode_requires_hashes(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("DAWARICH_MCP_TRANSPORT", "http")
    monkeypatch.setenv("DAWARICH_MCP_AUTH_MODE", "token")
    with pytest.raises(ConfigError, match="gen-token"):
        load_settings(transport="http")


def test_valid_http_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    _, digest = generate_token()
    monkeypatch.setenv("DAWARICH_MCP_TRANSPORT", "http")
    monkeypatch.setenv("DAWARICH_MCP_AUTH_TOKEN_HASHES", f"openwebui:{digest}")
    monkeypatch.setenv("DAWARICH_BASE_URL", "http://dawarich-app-1:3000")
    monkeypatch.setenv("DAWARICH_HOST_HEADER", "dawarich.example.com")
    settings = load_settings(transport="http")
    assert settings.auth_mode == "token"
    assert "openwebui" in settings.token_hashes.values()
    assert settings.dawarich_host_header == "dawarich.example.com"
    assert settings.dawarich_api_key is None


def test_bad_token_hash_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("DAWARICH_MCP_TRANSPORT", "http")
    monkeypatch.setenv("DAWARICH_MCP_AUTH_TOKEN_HASHES", "not-a-hash")
    with pytest.raises(ConfigError, match="sha256"):
        load_settings(transport="http")


def test_bad_upstream_url_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("DAWARICH_BASE_URL", "file:///etc")
    with pytest.raises(ConfigError, match="http\\(s\\) URL"):
        load_settings(transport="stdio")


def test_api_key_file_env_conflict(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    _clear_env(monkeypatch)
    key_file = tmp_path / "key"
    key_file.write_text("abc")
    monkeypatch.setenv("DAWARICH_API_KEY", "abc")
    monkeypatch.setenv("DAWARICH_API_KEY_FILE", str(key_file))
    with pytest.raises(ConfigError, match="not both"):
        load_settings(transport="stdio")
