#!/bin/bash
# Make small DMG fixtures for archivey on a Mac. Writes ~/dmg-fixtures.tar.gz.
set -uo pipefail
OUT="$HOME/dmg-fixtures"; rm -rf "$OUT"; mkdir -p "$OUT"
T="$(mktemp -d)"; SRC="$T/src"; mkdir -p "$SRC/sub dir"
printf 'hello dmg\n' > "$SRC/hello.txt"
printf 'caf\xc3\xa9\n' > "$SRC/sub dir/caf$(printf '\xc3\xa9').txt"
head -c 300000 /dev/urandom > "$SRC/random.bin"
yes 'compressible line' | head -n 20000 > "$SRC/text.txt"
ln -s hello.txt "$SRC/link-rel"; ln -s /Applications "$SRC/Applications"
ln "$SRC/hello.txt" "$SRC/sub dir/hardlink.txt"
xattr -w com.example.test 'xattr value' "$SRC/hello.txt"
sw_vers > "$OUT/macos-version.txt"
for FS in HFS+ APFS; do
  TAG=$( [ "$FS" = "HFS+" ] && echo hfs || echo apfs )
  RW="$T/rw-$TAG.dmg"; MNT="$T/mnt-$TAG"; mkdir -p "$MNT"
  hdiutil create -quiet -size 16m -fs "$FS" -volname Fixture -type UDIF "$RW" || { echo "create $FS failed"; continue; }
  hdiutil attach -quiet -nobrowse -noverify -mountpoint "$MNT" "$RW" || { echo "attach $FS failed"; continue; }
  ditto "$SRC" "$MNT"
  ditto --hfsCompression "$SRC/text.txt" "$MNT/compressed.txt"
  ( cd "$MNT" && ls -laRO . > "$OUT/$TAG-listing.txt"; find . -type f -exec shasum -a 256 {} + > "$OUT/$TAG-sha256.txt"; xattr -lr . > "$OUT/$TAG-xattrs.txt" 2>&1 )
  hdiutil detach -quiet "$MNT"
  cp "$RW" "$OUT/$TAG-UDRW.dmg"
  for F in UDZO UDBZ ULFO ULMO UDRO; do
    hdiutil convert -quiet "$RW" -format "$F" -o "$OUT/$TAG-$F.dmg" || echo "convert $TAG $F failed" >> "$OUT/skipped.txt"
  done
  for E in AES-128 AES-256; do
    printf 'archivey' | hdiutil convert -quiet "$RW" -format UDZO -encryption "$E" -stdinpass -o "$OUT/$TAG-UDZO-$E.dmg" \
      || echo "convert $TAG $E failed" >> "$OUT/skipped.txt"
  done
done
for D in "$OUT"/*.dmg; do echo "== $(basename "$D")"; head -c 8 "$D" | od -c | head -1; done > "$OUT/heads.txt"
tar czf "$HOME/dmg-fixtures.tar.gz" -C "$HOME" dmg-fixtures && ls -la "$HOME/dmg-fixtures.tar.gz"
rm -rf "$T"
