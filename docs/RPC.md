# RPC

JSON-lines parent/child protocol.

## Version

- `protocol_version: 1`
- Missing or mismatched versions fail fast.
- Child-side version mismatch exits `78`.

## Frame

```json
{
  "protocol_version": 1,
  "seq": 1,
  "msg": { "...": "..." }
}
```

- `seq` is strictly increasing per sender.
- Unknown fields are rejected.

## Messages

- `hello`
  - `role`: `parent` or `child`
  - `agent_id`
  - `policy_hash`
- `run`
  - `id`
  - `prompt`
- `cancel`
  - `id`
- `out`
  - `id`
  - `kind`: `text` or `info`
  - `text`
- `done`
  - `id`
  - `stop`: `done`, `canceled`, or `err`
  - `truncated`
- `err`
  - optional `id`
  - `code`
  - `message`
  - `fatal`

## Invariants

- `agent_id` must be valid and stable for the session.
- `policy_hash` is required on `hello` and must match.
- `run.id` must be valid and unique while active.
- Empty prompts, text, codes, or messages are invalid.
- Parent sends `hello` before `run`.
- Child must not emit output for a different active `id`.

## Driver

- `driverPathAlloc()` resolves the current executable with `std.fs.selfExePathAlloc`.
- Tests use `src/test/agent_exit_harness.zig` to prove the real mismatch exit code.
