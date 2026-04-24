# SPEC

## §G GOAL
enhance `pz` (zig) w/ all `free-code` (ts) features. perfect fast eng harness.

## §C CONSTRAINTS
- single static binary. 1.7MB goal.
- fast startup (3ms). memory idle 1.4MB.
- zero runtime deps (no node/bun).
- zig 0.15+.
- security-first: sandbox, egress policy, toctou guards.

## §I INTERFACES
- cmd: `pz [options]`
- tui: interactive streaming.
- headless: `--print`, `--json`, `rpc`.
- tool: 9 built-in + subagents.
- session: `.pz/` canonical state.
- config: `~/.pz/settings.json`, `~/.pz/auth.json`.

## §V INVARIANTS
V1: ∀ req → auth check before handler
V2: zero-alloc hot path ! maintained
V3: memory at idle ≤ 2MB
V4: binary size ≤ 3MB
V5: test coverage ≥ current (1300+ tests)

## §T TASKS
id|status|task|cites
T1|x|port AWAY_SUMMARY: idle sum REPL|-
T2|.|port HISTORY_PICKER: interactive prompt hist|-
T3|x|port HOOK_PROMPTS: pass text → hook flows|-
T4|x|port KAIROS_BRIEF: brief transcript layout|-
T5|x|port KAIROS_CHANNELS: channel notice/callbacks|-
T6|x|port LODESTONE: deep-link protocol reg|-
T7|x|port MESSAGE_ACTIONS: msg action UI|-
T8|x|port NEW_INIT: `/init` path|-
T9|x|port QUICK_SEARCH: prompt quick-search|-
T10|x|port SHOT_STATS: shot-dist stats views|-
T11|.|port TOKEN_BUDGET: budget track, triggers, UI|-
T12|x|port ULTRAPLAN: `/ultraplan` & exit-plan|-
T13|x|port VOICE_MODE: `/voice`, dictation, audio|-
T14|x|port AGENT_MEMORY_SNAPSHOT: store custom agent mem|-
T15|x|port AGENT_TRIGGERS: local cron/triggers|-
T16|x|port AGENT_TRIGGERS_REMOTE: remote trigger path|-
T17|x|port BUILTIN_EXPLORE_PLAN_AGENTS: explore/plan presets|-
T18|x|port CACHED_MICROCOMPACT: query/API flow microcompact|-
T19|x|port COMPACTION_REMINDERS: reminder copy compaction|-
T20|x|port EXTRACT_MEMORIES: post-query memory extract|-
T21|x|port PROMPT_CACHE_BREAK_DETECTION: cache-break detect|-
T22|x|port TEAMMEM: team-memory files & watcher|-
T23|x|port VERIFICATION_AGENT: verif agent guidance|-
T24|x|port BASH_CLASSIFIER: classifier-assist bash perm|-
T25|x|port BRIDGE_MODE: REPL bridge cmd & entitlement|-
T26|x|port CCR_AUTO_CONNECT: CCR auto-connect|-
T27|x|port CCR_MIRROR: outbound CCR mirror|-
T28|x|port CCR_REMOTE_SETUP: remote setup cmd|-
T29|x|port CHICAGO_MCP: computer-use MCP paths|-
T30|x|port CONNECTOR_TEXT: connector-text blocks|-
T31|x|port MCP_RICH_OUTPUT: rich MCP UI render|-
T32|x|port NATIVE_CLIPBOARD_IMAGE: native macOS clipboard fast path|-
T33|x|port POWERSHELL_AUTO_MODE: pwsh auto-mode perm|-
T34|x|port TREE_SITTER_BASH_SHADOW: ts bash shadow rollout|-
T35|x|port UNATTENDED_RETRY: API unattended retry|-
T36|x|port ABLATION_BASELINE: baseline entrypoint|-
T37|x|port ALLOW_TEST_VERSIONS: test versions native install|-
T38|x|port ANTI_DISTILLATION_CC: anti-distill metadata|-
T39|x|port BREAK_CACHE_COMMAND: break-cache cmd|-
T40|x|port COWORKER_TYPE_TELEMETRY: coworker telemetry|-
T41|x|port DOWNLOAD_USER_SETTINGS: settings sync pull|-
T42|x|port DUMP_SYSTEM_PROMPT: dump sys prompt path|-
T43|x|port FILE_PERSISTENCE: file persist plumbing|-
T44|x|port NATIVE_CLIENT_ATTESTATION: attestation marker|-
T45|x|port PERFETTO_TRACING: perfetto hooks|-
T46|x|port SKILL_IMPROVEMENT: skill-improvement hooks|-
T47|x|port SKIP_DETECTION_WHEN_AUTOUPDATES_DISABLED: skip update detect|-
T48|x|port SLOW_OPERATION_LOGGING: slow-op log|-
T49|x|port UPLOAD_USER_SETTINGS: settings sync push|-

## §B BUGS
id|date|cause|fix
