# pz

A security-first coding harness rewritten from the ground up in Zig for enterprise environments. `pz` is not a generic extensible agent platform, for now: the goal is peace of mind through built-in security, policy, auditability, and a single static binary.

## Why pz?

| | pi (TypeScript) | pz (Zig) |
|---|---|---|
| Binary size | ~10 MB + 589 MB node_modules | **1.7 MB** |
| Startup time | ~430 ms | **3 ms** |
| Memory at idle | ~153 MB | **1.4 MB** |
| Source lines | ~139k | **~29k** |
| Runtime deps | Node.js / Bun | **None** |
| Install | `bun install -g` | Copy one binary |

## Features

Pi-grade harness capabilities, with the product direction centered on built-in enterprise guardrails rather than extensibility:

- **Interactive TUI** — streaming responses, markdown rendering, syntax highlighting
- **Image rendering** — Kitty graphics protocol support in terminal
- **24 slash commands** — `/model`, `/fork`, `/export`, `/compact`, `/share`, `/tree`, and more
- **Autocomplete dropdown** — fuzzy-filtered command and file path completion
- **8 built-in tools** — `read`, `write`, `edit`, `bash`, `grep`, `find`, `ls`, `ask`
- **Session management** — persist, resume, fork, name, export, share as gist
- **OAuth + API key auth** — automatic token refresh, multi-provider support
- **Thinking modes** — adaptive and budget-capped extended thinking
- **Prompt caching** — automatic cache_control on system messages
- **Headless modes** — `--print`, `--json`, and `rpc` for scripting and integration
- **Zero-alloc hot path** — rendering and input handling avoid heap allocations
- **582 tests** — unit, integration, snapshot, and property tests

## Build

Requires [Zig](https://ziglang.org) 0.15+.

```
zig build -Doptimize=ReleaseFast
```

The binary lands in `zig-out/bin/pz`.

## Run

```
# Canonical state lives under ~/.pz/ and ./.pz/
pz

# Explicit provider and model
pz --provider anthropic --model claude-sonnet-4-20250514

# Headless
pz --print "explain this codebase"
echo '{"prompt":"hello"}' | pz --json
```

## Test

```
zig build test
```

## Changelog

- `CHANGELOG.md` for release-by-release notes
- `pz --changelog` or `/changelog` in TUI for in-app change visibility

## Config

Canonical `pz` state lives under `.pz/`:

- `~/.pz/settings.json` — global defaults
- `./.pz/settings.json` — project-local overrides
- `~/.pz/auth.json` — OAuth / API key credentials
- `~/.pz/state.json` — local machine state
- `~/.pz/sessions/` and `./.pz/sessions/` — persisted sessions
- `~/.pz/policy.json` and `./.pz/policy.json` — authoritative policy bundles
- `AGENTS.md` — policy-controlled context files

## License

MIT
