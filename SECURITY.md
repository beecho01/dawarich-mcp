# Security policy

## Reporting a vulnerability

Please open a private security advisory via GitHub (Security → Report a vulnerability)
rather than a public issue. Reports are acknowledged within a few days.

## Security model

`dawarich-mcp` exposes **read-only** location-history tools over a Dawarich
REST API. The security posture follows the [official MCP security best
practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
and the community checklist in [Puliczek/awesome-mcp-security](https://github.com/Puliczek/awesome-mcp-security):

- **Authentication, fail-closed.** HTTP mode refuses to start without either
  static bearer tokens (stored as SHA-256 hashes only — never the tokens) or
  OAuth 2.1 resource-server mode (JWKS-validated JWTs with audience checking,
  RFC 8707). No unauthenticated HTTP listener is possible by accident.
- **No token passthrough.** Client tokens are never forwarded upstream; Dawarich
  calls use the server's own API key, provided as a Docker secret file.
- **DNS-rebinding protection.** Host and Origin validation is always on for the
  HTTP transport (bad Origin → 403, bad Host → 421), per the MCP Streamable HTTP
  binding. (For contrast: Dawarich's own native MCP endpoint currently ships
  with this protection disabled.)
- **Stateless, POST-only.** 2026-07-28 semantics: no server-side sessions to
  hijack, no idle GET streams (405).
- **Input validation.** Strict JSON schemas on every tool argument; dates must
  be ISO 8601; window sizes and result counts are bounded.
- **Output sanitisation.** Every string is stripped of ANSI/OSC escapes,
  control characters, bidirectional overrides and zero-width characters, and
  length-capped, before it reaches a model's context. Known shapes
  (timestamps, coordinates, distances) are validated, not trusted.
- **Static tool list.** Tool names, descriptions and schemas are decided at
  startup and never swapped at runtime — no rug-pull / tool-poisoning surface.
  Descriptions contain no instructions to the model.
- **Rate limiting.** Per-principal token-bucket limiter with bounded memory.
- **Audit logging without PII.** JSON lines to stderr: tool, principal,
  outcome, duration. Coordinates and place names are never logged.
- **Hardened container.** read-only filesystem, `cap_drop: ALL`,
  `no-new-privileges`, non-root uid, tmpfs, memory/CPU/PID limits, no pip in
  the runtime image, security headers on every response.
- **Bounded upstream calls.** Fixed operator-configured base URL (never from
  arguments), redirects never followed, streamed response reads with byte
  caps, hard timeouts.
