#!/bin/sh
set -eu

repo_root=${1:-"$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"}
manifest=${2:-"$repo_root/deploy/frozen-v2-core.sha256"}

case "$manifest" in
    *.sha256)
        file_list=${manifest%.sha256}.files
        ;;
    *)
        exit 64
        ;;
esac

test -d "$repo_root"
test -f "$manifest"
test -f "$file_list"
LC_ALL=C sort -c -u "$file_list"

while IFS= read -r path || test -n "$path"; do
    test -n "$path"
    case "$path" in
        /* | .. | ../* | */.. | */../*)
            exit 1
            ;;
    esac
    test -f "$repo_root/$path"
    test ! -L "$repo_root/$path"
done <"$file_list"

manifest_files=$(mktemp)
trap 'rm -f "$manifest_files"' EXIT
LC_ALL=C awk '
    NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ { exit 1 }
    { print $2 }
' "$manifest" >"$manifest_files"
cmp -s "$file_list" "$manifest_files"

(
    cd "$repo_root"
    shasum -a 256 -c "$manifest"
)
