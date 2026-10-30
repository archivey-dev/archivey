#!/usr/bin/env bash
# Writes the test archives in this directory with GNU cpio 2.15 and bsdcpio 3.7.2
# (libarchive). Owners and times are pinned, and the file list is fixed, so running it
# again gives the same bytes for the same tool versions. Run as root: the tree has
# device nodes.
set -euo pipefail
cd "$(dirname "$0")"
tree="$(mktemp -d)"
trap 'rm -rf "$tree"' EXIT

mkdir -p "$tree/dir/sub" "$tree/empty"
printf 'hello\n' > "$tree/a.txt"
python3 -c "import random, sys; r = random.Random(1); sys.stdout.buffer.write(r.randbytes(10000))" > "$tree/dir/blocks.bin"
python3 -c "import sys; sys.stdout.write(''.join(f'line {i}\n' for i in range(2500)))" > "$tree/dir/sub/text.txt"
ln -s ../a.txt "$tree/dir/link"
ln "$tree/a.txt" "$tree/dir/hard.txt"
: > "$tree/zero.txt"
ln "$tree/zero.txt" "$tree/dir/zero-hard.txt"
mkfifo "$tree/fifo"
mknod "$tree/chr" c 1 3
mknod "$tree/blk" b 8 1
chown -hR 0:0 "$tree"
find "$tree" -exec touch -h -d @0 {} +

# a.txt comes before its link and zero.txt before its own, as find lists them.
list="a.txt
blk
chr
dir
dir/blocks.bin
dir/hard.txt
dir/link
dir/sub
dir/sub/text.txt
dir/zero-hard.txt
empty
fifo
zero.txt"

for fmt in bin odc newc crc; do
  (cd "$tree" && printf '%s\n' "$list" | cpio -o --quiet -H "$fmt" --reproducible) > "gnu-$fmt.cpio"
done
# bsdcpio has no binary writer for FIFOs, so only its two ASCII formats.
for fmt in odc newc; do
  (cd "$tree" && printf '%s\n' "$list" | bsdcpio -o --quiet --format "$fmt") > "bsd-$fmt.cpio"
done
