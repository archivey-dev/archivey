#!/bin/sh
# Rebuilds cpack-stgz.sh: a CPack STGZ installer (a shell script, then a .tar.gz)
# holding a.txt and sub/b.txt. Made with CMake 3.28.3; any CPack writes the same shape.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/src/sub" "$work/build"
printf 'hello\n' > "$work/src/a.txt"
printf 'second file\n' > "$work/src/sub/b.txt"
cat > "$work/src/CMakeLists.txt" <<'CMAKE'
cmake_minimum_required(VERSION 3.10)
project(demo VERSION 1.0 LANGUAGES NONE)
install(FILES a.txt DESTINATION .)
install(FILES sub/b.txt DESTINATION sub)
set(CPACK_GENERATOR STGZ)
set(CPACK_PACKAGE_FILE_NAME demo)
include(CPack)
CMAKE
cd "$work/build"
cmake ../src > /dev/null
cpack -G STGZ > /dev/null
cp demo.sh "$here/cpack-stgz.sh"
chmod 644 "$here/cpack-stgz.sh"
