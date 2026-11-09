"""Prototype: TAR salvage by header scan (aligned blocks + 'ustar' magic at any byte)."""
import sys; sys.path.insert(0, "/tmp/claude-0/sv/h"); from common import emit, tar_scan
buf = open(sys.argv[1], "rb").read()
emit([(n, d) for n, d, o in tar_scan(buf)])
