# Enterprise Deployment Reference

Operator-level reference for pz enterprise features: policy, audit, sandboxing, egress, storage, updates, and auth.

## Signed Policy Bundles

Policy bundles are JSON documents signed with Ed25519. The build-time public key is compiled into the binary; no runtime key distribution needed.

### Structure

```json
{
  "version": 1,
  "rules": [
    {"pattern": "tools/bash/*", "effect": "deny"},
    {"pattern": "tools/read/**", "effect": "allow", "tool": "read"}
  ],
  "lock": {"cfg": true, "env": true, "cli": true},
  "generation": 42,
  "not_after": 1735689600,
  "signature": "<hex>",
  "public_key": "<hex>"
}
```

### Key Concepts

- **Generation**: Monotonic counter stored in `.pz/policy-state.json`. Rollback (presenting a lower generation) is rejected. High-water mark persists across restarts.
- **Expiry** (`not_after`): Unix timestamp. Policy is rejected after this time. Omit for no expiry.
- **Lock mode**: Fine-grained locks prevent override of specific surfaces:
  - `cfg` — config file values (also disables session persistence)
  - `env` — environment variable overrides
  - `cli` — CLI flag overrides
  - `context` — context injection
  - `auth` — auth provider selection
  - `system_prompt` — system prompt modification
- **Verification**: Ed25519 signature checked against compiled-in public key (`signing.zig`). Constant-time comparison prevents timing attacks.
- **Merging**: Multiple signed bundles can be merged; generation takes max, expiry takes min.

### Deployment

1. Generate a keypair: keep seed offline, embed public key at build time via `build_options`.
2. Author policy JSON with rules, lock, generation, expiry.
3. Sign with `encodeSignedDoc()` using the keypair.
4. Distribute the signed JSON blob to endpoints.
5. pz loads and verifies on startup; rejects tampered, expired, or rolled-back bundles.

## Audit

Structured audit log with HMAC chain integrity and syslog shipping.

### Event Model

Every significant action emits an `audit.Entry` with:
- **Kind**: `sess`, `turn`, `tool`, `policy`, `auth`, `forward`, `ctrl`
- **Severity**: `debug`, `info`, `notice`, `warn`, `err`, `crit` (syslog-aligned)
- **Outcome**: `ok`, `deny`, `fail`
- **Actor/Resource/Data**: Structured fields with visibility annotations

### HMAC Chain (`audit_integrity.zig`)

Each log line is HMAC-SHA256 chained to its predecessor:
- Key ID + sequence number + previous MAC included in each line
- `SeqTracker` persists high-water mark to disk; replayed sequence numbers are rejected
- Verification: `Verify` union returns `ok` with state or `fail` with line number and failure kind (`malformed`, `unknown_key`, `bad_prev`, `bad_mac`, `replayed_seq`)

### Syslog Shipping (`syslog.zig`)

RFC 5424 compliant. Transports: UDP, TCP, TLS. Facility/severity mapping from audit severity to syslog priority. Structured data supported.

### Keyed Redaction

Fields carry a `Vis` (visibility) level: `pub`, `mask`, `hash`, `secret`.
- `RedactKey` derived per-session from session ID via HMAC-SHA256 with domain separation (`"pz-redact-v1"`)
- Same input + same key = same surrogate (enables correlation within a session)
- Different keys = different surrogates (decorrelates across sessions)
- Key rotation on new session ID automatically decorrelates old surrogates

## Tool Sandbox

### Process Groups

Background jobs (`bg.zig`) and bash tool executions run in their own process group (`pgid = 0`). Signals target the entire group.

### Environment Scrub (`sandbox.scrubEnv`)

Before spawning any child process, sensitive environment variables are removed:
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `PZ_API_KEY`, `PZ_AUTH_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, `GITLAB_TOKEN`, `NPM_TOKEN`, `DOCKER_AUTH_CONFIG`, `KUBECONFIG`, `SSH_AUTH_SOCK`.

### TERM then KILL

Graceful stop sequence:
1. Send `SIGTERM` to process group
2. Poll with `WNOHANG` up to ~150ms (15 iterations)
3. If not reaped, send `SIGKILL` to process group
4. Final blocking `waitpid` after KILL

Shutdown path sends `SIGKILL` immediately (no grace period).

### Protected Path Check (`shell.touchesProtectedPath`)

Shell commands are tokenized and checked against protected path patterns before execution. Applied in both the bash tool and background job `start()`.

### macOS Sandbox Profile

On macOS, bash tool execution is wrapped with `sandbox-exec` using a generated profile that:
- Restricts filesystem access to the workspace root and approved exec roots
- Limits executable paths to system directories and workspace

## Egress Policy

### Deny-by-Default

`EgressPolicy` evaluates outbound requests against path-pattern rules. No rules = no allowed endpoints.

### Endpoint Allowlists

Rules use the pattern `runtime/web/<host>` with tool scoping:
```json
{"pattern": "runtime/web/api.anthropic.com", "effect": "allow", "tool": "web"}
```

### Proxy

`proxy_url` field in egress policy. Constraints:
- Scheme must be `http://` or `https://` (no SOCKS)
- Proxy host itself must be allowed by egress rules
- Validated via `EgressPolicy.validatedProxy()`

### Deadlines

- Connect: default 10s, max 30s
- Total: default 30s, max 120s
- Configurable per-policy via `connect_deadline_ms` / `total_deadline_ms`

### IP Blocklist

RFC 1918, loopback, and link-local IPv4 addresses are blocked regardless of rules.

## Secure Local Storage

### `.pz/` Layout

- `.pz/policy-state.json` — policy generation high-water mark
- `.pz/upgrade` — update policy path
- `.pz/policy.json` — update policy file
- Session files under state directory

### Filesystem Hardening (`fs_secure.zig`)

- Directories created with mode `0o700`, files with `0o600`
- `openConfined()`: opens files with `O_NOFOLLOW`, rejects symlinks and hardlinks (`nlink != 1`)
- Atomic writes via `createFileAt` with restrictive modes
- Path validation: leaf-only names, no directory traversal

## Self-Update Verification

### Signed Manifests

Release assets include a `.manifest` signature file. Update flow:
1. Fetch latest release metadata from GitHub API
2. Download binary asset and corresponding `.manifest`
3. Verify Ed25519 signature against compiled-in public key
4. Policy check: update path evaluated against policy rules

### Crash-Safe Install

Binary replacement uses atomic file operations. On failure, the original binary is preserved.

### Update Policy

Controlled by `.pz/policy.json` — rules can restrict which release URLs are allowed (`release_url` field in policy doc).

## Auth

### OAuth + API Key

- OAuth callback server (`oauth_callback.zig`) for browser-based auth flows
- API key auth via environment variables or config files
- Auth surface lockable via signed policy (`lock.auth`)

### CA Bundle

Custom CA bundle support via `tls.zig` and `app/tls.zig`. Policy `ca_file` field overrides system CA store for corporate environments with internal CAs.

### Browser Launch

OAuth flows launch the system browser with absolute paths only. No `PATH`-relative resolution.
