#!/usr/bin/env bash
# Writes the test packages in this directory with rpmbuild (rpm 4.18.2): one binary
# package per payload compressor rpm offers, and the source package. Build times and
# file times are pinned to SOURCE_DATE_EPOCH, so running it again with the same rpm
# gives the same file list and contents. Run as root: the package has a device node.
#
# A payload in the stripped CPIO form (07070X), which RPM 6 and RPM 4 packages with a
# file of 4 GiB or more use, is built by tests/test_rpm.py itself: rpm 4.18 writes it
# only for such a file.
set -euo pipefail
cd "$(dirname "$0")"
top="$(mktemp -d)"
trap 'rm -rf "$top"' EXIT
export SOURCE_DATE_EPOCH=1700000000

cat > "$top/archivey-test.spec" <<'SPEC'
Name: archivey-test
Version: 1.0
Release: 1
Epoch: 2
Summary: archivey's RPM test package
License: MIT
BuildArch: noarch
%description
A package of each member type archivey lists.
%install
mkdir -p %{buildroot}/usr/share/at/dir/sub %{buildroot}/usr/share/at/empty %{buildroot}/usr/bin
printf 'hello\n' > %{buildroot}/usr/share/at/a.txt
ln %{buildroot}/usr/share/at/a.txt %{buildroot}/usr/share/at/dir/hard.txt
python3 -c "import random, sys; r = random.Random(1); sys.stdout.buffer.write(r.randbytes(10000))" > %{buildroot}/usr/share/at/dir/blocks.bin
python3 -c "import sys; sys.stdout.write(''.join(f'line {i}\n' for i in range(2500)))" > %{buildroot}/usr/share/at/dir/sub/text.txt
: > %{buildroot}/usr/share/at/zero.txt
ln %{buildroot}/usr/share/at/zero.txt %{buildroot}/usr/share/at/dir/zero-hard.txt
ln -s ../a.txt %{buildroot}/usr/share/at/dir/link
printf '#!/bin/sh\necho hi\n' > %{buildroot}/usr/bin/at-hi
chmod 755 %{buildroot}/usr/bin/at-hi
%files
%attr(0755,root,root) /usr/bin/at-hi
%dir /usr/share/at
/usr/share/at/a.txt
/usr/share/at/dir
/usr/share/at/empty
/usr/share/at/zero.txt
%ghost /usr/share/at/ghost.log
%attr(0644,root,root) %dev(c,1,3) /usr/share/at/chr
SPEC

build() {
  rpmbuild --quiet --define "_topdir $top/build" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "clamp_mtime_to_source_date_epoch 1" \
    --define "_buildhost archivey.test" \
    "$@" "$top/archivey-test.spec"
}

for payload in gzip:w9.gzdio xz:w2.xzdio zstd:w3.zstdio bzip2:w9.bzdio lzma:w2.lzdio none:w.ufdio; do
  name="${payload%%:*}"
  build -bb --define "_binary_payload ${payload#*:}"
  mv "$top"/build/RPMS/noarch/*.rpm "payload-$name.rpm"
done
build -bs --define "_source_payload w9.gzdio"
mv "$top"/build/SRPMS/*.rpm source.rpm
