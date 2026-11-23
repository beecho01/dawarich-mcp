"""Static bearer-token auth: hashing, verification and rejection."""

from __future__ import annotations

import anyio
import pytest

from dawarich_mcp.auth import StaticTokenVerifier, generate_token, hash_token


def test_generate_token_shape_and_hash_roundtrip() -> None:
    token, digest = generate_token()
    assert token.startswith("dwmcp_")
    assert len(digest) == 64
    assert hash_token(token).hex() == digest


def test_verifier_accepts_known_token() -> None:
    token, digest = generate_token()
    verifier = StaticTokenVerifier({bytes.fromhex(digest): "label"})
    access = anyio.run(verifier.verify_token, token)
    assert access is not None
    assert access.client_id == "label"
    assert "dwmcp_" not in access.token  # only a fingerprint is retained


@pytest.mark.parametrize("bad", ["", "dwmcp_nope", "A" * 9000, "Bearer "])
def test_verifier_rejects_unknown_or_malformed(bad: str) -> None:
    _, digest = generate_token()
    verifier = StaticTokenVerifier({bytes.fromhex(digest): "label"})
    assert anyio.run(verifier.verify_token, bad) is None
