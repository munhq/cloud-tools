#!/usr/bin/env bash
# Hold every place that names a release asset to the release matrix itself.
#
# Three files independently decide which asset to download: npm/bin/resolve.js,
# install.sh, and the Dockerfile. They are written in three languages and edited
# at different times, so they drift, and the drift is invisible until a stranger
# on the affected platform gets a 404 that reads as "there is no build for me".
#
# .github/workflows/release.yml is the source of truth. Add a target there
# without teaching the scripts about it, or rename an asset, and this fails here
# instead of in someone's editor.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
workflow="$root/.github/workflows/release.yml"

# Every asset the release matrix publishes, assembled from the same three fields
# the workflow's own staging step uses.
published="$(awk '
    /^ *- target:/ { arch=""; plat=""; ext="" }
    /^ *arch:/ { arch=$2 }
    /^ *plat:/ { plat=$2 }
    /^ *ext:/  { ext=$2; gsub(/"/, "", ext)
                 if (arch && plat) print "cloud-tools-" arch "-" plat ext }
' "$workflow" | sort -u)"
if [ -z "$published" ]; then
    echo "could not read the matrix from $workflow" >&2
    exit 1
fi
echo "release.yml publishes:"
printf '  %s\n' $published
echo

fail=0
checked=0

# Quoted, and -F, deliberately. This is called from inside a loop that sets
# IFS='|' to split the case table, and an unquoted expansion there is re-split on
# whatever IFS happens to be rather than on newlines. The asset names also carry
# a dot, which -F stops grep reading as a pattern.
is_published() {
    printf '%s\n' "$published" | grep -qxF -- "$1"
}

# ── 1. the npm resolver ──────────────────────────────────────────────────────
# selftest.js prints `platform<TAB>arch<TAB>asset` for every platform the wrapper
# claims. Every one must be a real asset, and every real asset must be claimed.
resolved="$(cd "$here" && node bin/selftest.js 2>/dev/null | cut -f3 | sort -u)"
for asset in $resolved; do  # default IFS here: one name per line
    checked=$((checked + 1))
    if ! is_published "$asset"; then
        echo "FAIL resolve.js offers $asset, which the release does not publish" >&2
        fail=$((fail + 1))
    fi
done
for asset in $published; do
    checked=$((checked + 1))
    if ! printf '%s\n' "$resolved" | grep -qxF -- "$asset"; then
        echo "FAIL the release publishes $asset, which resolve.js never asks for" >&2
        fail=$((fail + 1))
    fi
done

# ── 2. install.sh ────────────────────────────────────────────────────────────
# uname pairs a real machine reports, and the asset each must resolve to. The
# left side is what `uname -m` and `uname -s` print; the right side is asserted
# against the matrix above, not taken on trust.
cases="
x86_64|Linux|cloud-tools-x86_64-linux
amd64|Linux|cloud-tools-x86_64-linux
aarch64|Linux|cloud-tools-aarch64-linux
arm64|Linux|cloud-tools-aarch64-linux
x86_64|Darwin|cloud-tools-x86_64-macos
arm64|Darwin|cloud-tools-aarch64-macos
aarch64|Darwin|cloud-tools-aarch64-macos
x86_64|MINGW64_NT-10.0-22631|cloud-tools-x86_64-windows.exe
x86_64|MSYS_NT-10.0-19045|cloud-tools-x86_64-windows.exe
x86_64|CYGWIN_NT-10.0|cloud-tools-x86_64-windows.exe
arm64|MINGW64_NT-10.0|cloud-tools-aarch64-windows.exe
aarch64|Windows_NT|cloud-tools-aarch64-windows.exe
"

fake_uname_dir() {
    d="$(mktemp -d)"
    cat >"$d/uname" <<EOF
#!/bin/sh
case "\$1" in
    -m) echo "$1" ;;
    -s) echo "$2" ;;
    *)  echo "$2" ;;
esac
EOF
    chmod +x "$d/uname"
    printf '%s\n' "$d"
}

while IFS='|' read -r machine system want; do
    [ -n "${machine:-}" ] || continue
    checked=$((checked + 1))

    if ! is_published "$want"; then
        echo "FAIL the case table expects $want, which the release does not publish" >&2
        fail=$((fail + 1))
        continue
    fi

    d="$(fake_uname_dir "$machine" "$system")"
    got="$(PATH="$d:$PATH" bash "$root/install.sh" --print-artifact 2>/dev/null)"
    rm -rf "$d"

    if [ "$got" != "$want" ]; then
        echo "FAIL install.sh on $machine/$system asks for '${got:-nothing}', expected $want" >&2
        fail=$((fail + 1))
    fi
done <<EOF
$cases
EOF

# ── 3. the Dockerfile ────────────────────────────────────────────────────────
# Docker's vocabulary is amd64/arm64, and the image is Linux only.
for pair in "amd64 cloud-tools-x86_64-linux" "arm64 cloud-tools-aarch64-linux"; do
    set -- $pair
    checked=$((checked + 1))
    if ! grep -q "ASSET=\"$2\"" "$root/Dockerfile"; then
        echo "FAIL Dockerfile does not map TARGETARCH=$1 to $2" >&2
        fail=$((fail + 1))
    fi
done

if [ "$fail" -ne 0 ]; then
    echo >&2
    echo "$fail of $checked checks failed" >&2
    exit 1
fi
echo "$checked checks passed: the resolver, install.sh and the Dockerfile all match the release matrix."
