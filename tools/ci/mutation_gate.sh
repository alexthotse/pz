#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

survivors=()

run_case() {
    local name="$1"
    local file="$2"
    local from="$3"
    local to="$4"
    local test_cmd="$5"

    local backup
    backup="$(mktemp)"
    local log
    log="$(mktemp)"
    cp "$file" "$backup"

    if ! grep -Fq "$from" "$file"; then
        echo "mutation gate misconfigured: pattern not found for $name in $file" >&2
        cp "$backup" "$file"
        rm -f "$backup" "$log"
        exit 2
    fi

    FROM="$from" TO="$to" perl -0pi -e 's/\Q$ENV{FROM}\E/$ENV{TO}/' "$file"

    if cmp -s "$file" "$backup"; then
        echo "mutation gate misconfigured: replacement had no effect for $name" >&2
        cp "$backup" "$file"
        rm -f "$backup" "$log"
        exit 2
    fi

    set +e
    bash -lc "$test_cmd" >"$log" 2>&1
    local rc=$?
    set -e

    cp "$backup" "$file"
    rm -f "$backup"

    if [[ $rc -eq 0 ]]; then
        survivors+=("$name")
        echo "SURVIVED $name" >&2
        cat "$log" >&2
    else
        echo "KILLED   $name"
    fi
    rm -f "$log"
}

run_case \
    "openai-stop-failed-maps-err" \
    "src/core/providers/openai.zig" \
    ".{ \"failed\", .err }," \
    ".{ \"failed\", .done }," \
    "zig test src/core/providers/openai.zig -O Debug"

run_case \
    "openai-tool-stop-on-completed" \
    "src/core/providers/openai.zig" \
    "if (self.saw_tool_call and stop_reason == .done) stop_reason = .tool;" \
    "if (self.saw_tool_call and stop_reason == .done) stop_reason = .done;" \
    "zig test src/core/providers/openai.zig -O Debug"

run_case \
    "auth-env-oauth-precedence" \
    "src/core/providers/auth.zig" \
    "if (token.len > 0) return .{ .oauth = .{" \
    "if (token.len > 99999999) return .{ .oauth = .{" \
    "zig test src/core/providers/auth.zig -O Debug"

run_case \
    "auth-oauth-file-type-map" \
    "src/core/providers/auth.zig" \
    ".{ \"oauth\", .oauth }," \
    ".{ \"oauth\", .api_key }," \
    "zig test src/core/providers/auth.zig -O Debug"

run_case \
    "stream-parse-stop-err-map" \
    "src/core/providers/stream_parse.zig" \
    ".{ \"err\", .err }," \
    ".{ \"err\", .done }," \
    "zig test src/core/providers/stream_parse.zig -O Debug"

if ((${#survivors[@]} > 0)); then
    printf "mutation survivors (%d):\n" "${#survivors[@]}" >&2
    printf "  - %s\n" "${survivors[@]}" >&2
    exit 1
fi

echo "mutation gate passed"
