#!/usr/bin/env bash
# Writes the test packages in this directory with dpkg-deb 1.22.6. Times are pinned
# (SOURCE_DATE_EPOCH) and owners are root (--root-owner-group), so running it again
# gives the same bytes for the same dpkg-deb and compressor versions.
set -euo pipefail
cd "$(dirname "$0")"
tree="$(mktemp -d)"
trap 'rm -rf "$tree"' EXIT
export SOURCE_DATE_EPOCH=1700000000

pkg="$tree/pkg"
mkdir -p "$pkg/DEBIAN" "$pkg/usr/bin" "$pkg/usr/share/doc/hello"
cat > "$pkg/DEBIAN/control" <<'CONTROL'
Package: hello
Version: 1.0-1
Architecture: all
Maintainer: Archivey Tests <tests@example.invalid>
Description: a package for archivey's tests
 Two lines of description.
CONTROL
printf '#!/bin/sh\nexit 0\n' > "$pkg/DEBIAN/postinst"
chmod 755 "$pkg/DEBIAN/postinst"
printf '#!/bin/sh\necho hello\n' > "$pkg/usr/bin/hello"
chmod 755 "$pkg/usr/bin/hello"
python3 -c "import random, sys; sys.stdout.buffer.write(random.Random(1).randbytes(5001))" > "$pkg/usr/share/doc/hello/data.bin"
ln -s ../../../bin/hello "$pkg/usr/share/doc/hello/link"
ln "$pkg/usr/bin/hello" "$pkg/usr/bin/hello-hard"
(cd "$pkg" && find usr -type f -print0 | sort -z | xargs -0 md5sum > DEBIAN/md5sums)
find "$pkg" -exec touch -h -d @"$SOURCE_DATE_EPOCH" {} +

rm -f ./*.deb
for z in xz gzip zstd; do
    dpkg-deb --root-owner-group -Z"$z" --build "$pkg" "hello-$z.deb" >/dev/null
done
