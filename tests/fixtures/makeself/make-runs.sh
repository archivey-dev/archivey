#!/usr/bin/env bash
# Writes the test archives in this directory with makeself's own scripts, one release
# at a time: a checkout of https://github.com/megastep/makeself is the argument, and
# each archive is made with `makeself.sh` and `makeself-header.sh` from the tag its name
# carries (gzip-2.4.0.run with release-2.4.0). File times are pinned, so running it
# again gives the same TARs; the headers hold the build date. Needs gzip, bzip2, xz,
# zstd, lz4, lzop and openssl.
#
# The scripts are GPL-2.0 (makeself's license). The archives they write carry that
# header, as every makeself archive does; makeself states that the license of an
# archive's contents is independent of it.
set -euo pipefail
repo="$(cd "$1" && pwd)"
cd "$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/content/sub" "$work/more"
printf 'hello\n' > "$work/content/a.txt"
printf 'second file\n' > "$work/content/sub/b.txt"
ln -s a.txt "$work/content/link"
printf '#!/bin/sh\necho installed\n' > "$work/content/setup.sh"
chmod 755 "$work/content/setup.sh"
printf 'appended\n' > "$work/more/c.txt"
find "$work/content" "$work/more" -exec touch -h -d '2026-01-02 03:04:05 UTC' {} +

tool() {
    local version="$1"
    if [ ! -d "$work/v$version" ]; then
        mkdir "$work/v$version"
        git -C "$repo" archive "release-$version" makeself.sh makeself-header.sh \
            | tar -x -C "$work/v$version"
    fi
    echo "$work/v$version/makeself.sh"
}

make() {
    local version="$1" name="$2"
    shift 2
    rm -f "$name"
    sh "$(tool "$version")" --nox11 "$@" "$work/content" "$name" "Label $version" \
        ./setup.sh > /dev/null
}

for version in 2.2.0 2.4.0 2.4.5 2.7.1; do
    make "$version" "gzip-$version.run"
done
for compressor in bzip2 xz zstd lz4 lzo nocomp base64; do
    make 2.7.1 "$compressor-2.7.1.run" "--$compressor"
done
make 2.7.1 sha256-2.7.1.run --sha256
make 2.7.1 openssl-2.7.1.run --ssl-encrypt --ssl-passwd secret
make 2.4.0 base64-2.4.0.run --base64
# Two payloads: makeself 2.2.0 to 2.4.0 append one for each --append.
make 2.4.0 append-2.4.0.run
sh "$(tool 2.4.0)" --nox11 --append "$work/more" append-2.4.0.run > /dev/null
