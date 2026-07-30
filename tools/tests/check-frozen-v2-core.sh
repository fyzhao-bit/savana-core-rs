#!/bin/sh
set -eu

checker=$1
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

mkdir -p "$fixture/core" "$fixture/deploy"
printf 'alpha\n' >"$fixture/core/a"
printf 'beta\n' >"$fixture/core/b"
printf 'core/a\ncore/b\n' >"$fixture/deploy/frozen-v2-core.files"
(
    cd "$fixture"
    shasum -a 256 core/a core/b
) >"$fixture/deploy/frozen-v2-core.sha256"

"$checker" "$fixture" "$fixture/deploy/frozen-v2-core.sha256"

expect_rejected() {
    if "$checker" "$fixture" "$fixture/deploy/frozen-v2-core.sha256"; then
        printf 'frozen-core checker accepted invalid fixture: %s\n' "$1" >&2
        exit 1
    fi
}

printf 'changed\n' >"$fixture/core/b"
expect_rejected 'changed content'
printf 'beta\n' >"$fixture/core/b"

printf 'core/b\ncore/a\n' >"$fixture/deploy/frozen-v2-core.files"
expect_rejected 'unsorted file list'

printf 'core/a\ncore/a\n' >"$fixture/deploy/frozen-v2-core.files"
expect_rejected 'duplicate file list entry'

printf '/core/a\ncore/b\n' >"$fixture/deploy/frozen-v2-core.files"
expect_rejected 'absolute path'

printf '../core/a\ncore/b\n' >"$fixture/deploy/frozen-v2-core.files"
expect_rejected 'parent traversal'

printf 'core/a\ncore/missing\n' >"$fixture/deploy/frozen-v2-core.files"
expect_rejected 'missing file'
