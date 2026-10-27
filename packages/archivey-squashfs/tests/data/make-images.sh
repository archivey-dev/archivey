#!/usr/bin/env bash
# Writes the test images in this directory with mksquashfs (squashfs-tools 4.6.1).
# Every option that varies between runs is pinned (owner, times, padding), so running
# it again gives the same bytes for the same squashfs-tools version.
set -euo pipefail
cd "$(dirname "$0")"
tree="$(mktemp -d)"
trap 'rm -rf "$tree"' EXIT

mkdir -p "$tree/dir/sub" "$tree/empty"
printf 'hello\n' > "$tree/a.txt"
# Two full 4 KiB blocks and a tail that lands in a fragment.
python3 -c "import random, sys; r = random.Random(1); sys.stdout.buffer.write(r.randbytes(10000))" > "$tree/dir/blocks.bin"
python3 -c "import sys; sys.stdout.write(''.join(f'line {i}\n' for i in range(2500)))" > "$tree/dir/sub/text.txt"
ln -s ../a.txt "$tree/dir/link"
ln "$tree/a.txt" "$tree/dir/hard.txt"
# Four blocks, the middle two all zeros: stored as sparse blocks.
python3 -c "import sys; sys.stdout.buffer.write(b'x' * 4096 + bytes(8192) + b'y' * 4096)" > "$tree/sparse.bin"
mkfifo "$tree/fifo"

common=(-noappend -all-root -mkfs-time 0 -all-time 0 -nopad -no-xattrs -b 4096 -quiet
        -no-progress -p "chr c 0644 0 0 1 3" -p "blk b 0600 0 0 8 1")
for comp in gzip xz lzma lz4 zstd lzo; do
  mksquashfs "$tree" "$comp.sqfs" -comp "$comp" "${common[@]}"
done
mksquashfs "$tree" uncompressed.sqfs -noI -noD -noF "${common[@]}"
mksquashfs "$tree" no-fragments.sqfs -no-fragments "${common[@]}"
mksquashfs "$tree" xz-bcj.sqfs -comp xz -Xbcj x86 "${common[@]}"
# Tail ends of larger files in fragments too (off by default since 4.6).
mksquashfs "$tree" tail-ends.sqfs -tailends "${common[@]}"
# LZO with liblzo's fast compressor; the default is lzo1x_999, which codes differently.
mksquashfs "$tree" lzo1x-1.sqfs -comp lzo -Xalgorithm lzo1x_1 "${common[@]}"
