"""Win32 error codes that archivey matches on ``OSError.winerror``.

``winerror`` exists only on Windows, so a match reads it with ``getattr(exc,
"winerror", None)``. Each code is defined here once, for every module that matches it.
"""

from __future__ import annotations

ERROR_PATH_NOT_FOUND = 3
ERROR_INVALID_NAME = 123
# A path that is too long, and also a command line over 32 767 characters that
# ``CreateProcess`` refuses. Python maps it to ENOENT.
ERROR_FILENAME_EXCED_RANGE = 206
ERROR_TOO_MANY_LINKS = 1142
ERROR_PRIVILEGE_NOT_HELD = 1314
# A path whose links do not resolve: Windows' equivalent of ``ELOOP``.
ERROR_CANT_RESOLVE_FILENAME = 1921
