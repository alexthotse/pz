#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

base_ref="${PZ_TEST_IMPACT_BASE:-}"

if [[ -z "$base_ref" ]]; then
    if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
        base_ref="origin/${GITHUB_BASE_REF}"
    elif git rev-parse --verify origin/main >/dev/null 2>&1; then
        base_ref="origin/main"
    else
        base_ref="HEAD~1"
    fi
fi

if [[ "$base_ref" == origin/* ]]; then
    git fetch --no-tags --depth=1 origin "${base_ref#origin/}" >/dev/null 2>&1 || true
fi

if ! git rev-parse --verify "$base_ref" >/dev/null 2>&1; then
    echo "test-impact gate: unable to resolve base ref '$base_ref'" >&2
    exit 2
fi

if merge_base="$(git merge-base "$base_ref" HEAD 2>/dev/null)"; then
    range="${merge_base}...HEAD"
else
    if git rev-parse --verify HEAD~1 >/dev/null 2>&1; then
        range="HEAD~1...HEAD"
    else
        echo "test-impact gate: unable to compute merge base for '$base_ref'" >&2
        exit 2
    fi
fi

changed_src="$(git diff --name-only "$range" -- src | rg '\.zig$' || true)"
if [[ -z "$changed_src" ]]; then
    echo "test-impact gate: no Zig source changes"
    exit 0
fi

added_lines="$(git diff -U0 "$range" -- src | rg '^\+[^+]' || true)"
test_signal="$(printf '%s\n' "$added_lines" | rg '\btest\s+\"|oh\.snap\(|expect\(|expectEqual\(|expectError\(' || true)"

if [[ -z "$test_signal" ]]; then
    echo "test-impact gate: Zig source changed without test/assert deltas" >&2
    echo "changed files:" >&2
    printf '%s\n' "$changed_src" >&2
    exit 1
fi

echo "test-impact gate passed"
