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
T1|.|port AWAY_SUMMARY: idle sum REPL|-
T2|.|port HISTORY_PICKER: interactive prompt hist|-
T3|.|port HOOK_PROMPTS: pass text → hook flows|-
T4|.|port KAIROS_BRIEF: brief transcript layout|-
T5|.|port KAIROS_CHANNELS: channel notice/callbacks|-
T6|.|port LODESTONE: deep-link protocol reg|-
T7|.|port MESSAGE_ACTIONS: msg action UI|-
T8|.|port NEW_INIT: `/init` path|-
T9|.|port QUICK_SEARCH: prompt quick-search|-
T10|.|port SHOT_STATS: shot-dist stats views|-
T11|.|port TOKEN_BUDGET: budget track, triggers, UI|-
T12|.|port ULTRAPLAN: `/ultraplan` & exit-plan|-
T13|.|port VOICE_MODE: `/voice`, dictation, audio|-
T14|.|port AGENT_MEMORY_SNAPSHOT: store custom agent mem|-
T15|.|port AGENT_TRIGGERS: local cron/triggers|-
T16|.|port AGENT_TRIGGERS_REMOTE: remote trigger path|-
T17|.|port BUILTIN_EXPLORE_PLAN_AGENTS: explore/plan presets|-
T18|.|port CACHED_MICROCOMPACT: query/API flow microcompact|-
T19|.|port COMPACTION_REMINDERS: reminder copy compaction|-
T20|.|port EXTRACT_MEMORIES: post-query memory extract|-
T21|.|port PROMPT_CACHE_BREAK_DETECTION: cache-break detect|-
T22|.|port TEAMMEM: team-memory files & watcher|-
T23|.|port VERIFICATION_AGENT: verif agent guidance|-
T24|.|port BASH_CLASSIFIER: classifier-assist bash perm|-
T25|.|port BRIDGE_MODE: REPL bridge cmd & entitlement|-
T26|.|port CCR_AUTO_CONNECT: CCR auto-connect|-
T27|.|port CCR_MIRROR: outbound CCR mirror|-
T28|.|port CCR_REMOTE_SETUP: remote setup cmd|-
T29|.|port CHICAGO_MCP: computer-use MCP paths|-
T30|.|port CONNECTOR_TEXT: connector-text blocks|-
T31|.|port MCP_RICH_OUTPUT: rich MCP UI render|-
T32|.|port NATIVE_CLIPBOARD_IMAGE: native macOS clipboard fast path|-
T33|.|port POWERSHELL_AUTO_MODE: pwsh auto-mode perm|-
T34|.|port TREE_SITTER_BASH_SHADOW: ts bash shadow rollout|-
T35|.|port UNATTENDED_RETRY: API unattended retry|-
T36|.|port ABLATION_BASELINE: baseline entrypoint|-
T37|.|port ALLOW_TEST_VERSIONS: test versions native install|-
T38|.|port ANTI_DISTILLATION_CC: anti-distill metadata|-
T39|.|port BREAK_CACHE_COMMAND: break-cache cmd|-
T40|.|port COWORKER_TYPE_TELEMETRY: coworker telemetry|-
T41|.|port DOWNLOAD_USER_SETTINGS: settings sync pull|-
T42|.|port DUMP_SYSTEM_PROMPT: dump sys prompt path|-
T43|.|port FILE_PERSISTENCE: file persist plumbing|-
T44|.|port NATIVE_CLIENT_ATTESTATION: attestation marker|-
T45|.|port PERFETTO_TRACING: perfetto hooks|-
T46|.|port SKILL_IMPROVEMENT: skill-improvement hooks|-
T47|.|port SKIP_DETECTION_WHEN_AUTOUPDATES_DISABLED: skip update detect|-
T48|.|port SLOW_OPERATION_LOGGING: slow-op log|-
T49|.|port UPLOAD_USER_SETTINGS: settings sync push|-

## §B BUGS
id|date|cause|fix
