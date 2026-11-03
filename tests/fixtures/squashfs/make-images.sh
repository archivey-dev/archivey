#!/usr/bin/env bash
# Writes the test images in this directory with mksquashfs and sqfstar (squashfs-tools 4.6.1).
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
# A 1 GiB file of holes at the default 128 KiB blocks: its 32 KiB block list of zeros
# decodes to more than the compressed inode table holds on disk.
holes="$(mktemp -d)"
trap 'rm -rf "$tree" "$holes"' EXIT
truncate -s 1G "$holes/holes.bin"
python3 -c "import random, sys; r = random.Random(2); sys.stdout.buffer.write(r.randbytes(5000))" > "$holes/data.bin"
mksquashfs "$holes" large-sparse.sqfs -noappend -all-root -mkfs-time 0 -all-time 0 -nopad \
  -no-xattrs -quiet -no-progress

# Fragments filled in an order other than the listing's. sqfstar packs tails in the
# order the tar holds them, and the listing is in name order: f0 to f9, two to a 4 KiB
# fragment, are stored f0 f5 | f1 f6 | f2 f7 | f3 f8 | f4 f9, so name order cycles
# through five fragment blocks, one more than the reader keeps.
tar_tree="$(mktemp -d)"
trap 'rm -rf "$tree" "$holes" "$tar_tree"' EXIT
mkdir "$tar_tree/d"
for i in 0 1 2 3 4 5 6 7 8 9 10; do
  name="f$i"; [ "$i" = 10 ] && name="d/f10"
  python3 -c "import random, sys; sys.stdout.buffer.write(random.Random($i).randbytes(100) * 15)" > "$tar_tree/$name"
done
python3 -c "import random, sys; sys.stdout.buffer.write(random.Random(11).randbytes(64) * 64)" > "$tar_tree/big"
ln -s f0 "$tar_tree/link"
ln "$tar_tree/f3" "$tar_tree/hard"
tar -C "$tar_tree" -cf - --format=gnu --numeric-owner --owner=0 --group=0 --mtime=@0 \
  --no-recursion f0 f5 f1 f6 f2 f7 f3 f8 f4 f9 d d/f10 big link hard \
  | sqfstar -b 4096 -mkfs-time 0 -all-time 0 -nopad -no-xattrs -quiet -no-progress \
    -all-root -force tar-order.sqfs
# The same files and four larger ones with tails (f0t ...) from mksquashfs -tailends, which
# fills small files and tail ends as two streams, each in name order: the listing needs
# two fragment blocks at a time, fewer than are kept.
for i in 0 2 4 6; do
  python3 -c "import random, sys; sys.stdout.buffer.write(random.Random(20 + $i).randbytes(64) * 88)" > "$tar_tree/f${i}t"
done
mksquashfs "$tar_tree" tail-ends-two-streams.sqfs -tailends "${common[@]}"
