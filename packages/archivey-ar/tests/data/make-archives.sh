#!/usr/bin/env bash
# Writes the test archives in this directory with GNU ar 2.42, bsdtar 3.7.2 (libarchive)
# and llvm-ar 18. Owners and times are pinned, so running it again gives the same bytes
# for the same tool versions (sym.o comes from the C compiler, and its bytes follow the
# compiler's version).
set -euo pipefail
cd "$(dirname "$0")"
tree="$(mktemp -d)"
trap 'rm -rf "$tree"' EXIT

printf 'hello\n' > "$tree/a.txt"
# An odd length, so the member is followed by a pad byte.
python3 -c "import random, sys; sys.stdout.buffer.write(random.Random(1).randbytes(1001))" > "$tree/odd.bin"
printf 'long\n' > "$tree/a-file-name-longer-than-sixteen.txt"
# An object file, so that the archivers write a symbol table.
printf 'int answer(void) { return 42; }\n' > "$tree/sym.c"
cc -c -O0 -o "$tree/sym.o" "$tree/sym.c"
chown -R 0:0 "$tree"
find "$tree" -exec touch -d @0 {} +

files=(a.txt odd.bin a-file-name-longer-than-sixteen.txt sym.o)
rm -f gnu.a bsd.a darwin.a thin.a
# GNU: a "/" symbol table, then a "//" long-name table.
(cd "$tree" && ar rcsD "$OLDPWD/gnu.a" "${files[@]}")
# BSD: long names in the data area ("#1/35"), no symbol table.
(cd "$tree" && bsdtar --format arbsd -cf "$OLDPWD/bsd.a" "${files[@]}")
# macOS: every name in the data area, NUL-padded, after a "__.SYMDEF" symbol table.
(cd "$tree" && llvm-ar rcsD --format=darwin "$OLDPWD/darwin.a" "${files[@]}")
# Thin: the members stay outside the archive.
(cd "$tree" && ar rcTD "$OLDPWD/thin.a" a.txt)
