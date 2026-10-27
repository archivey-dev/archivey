"""Format backends — one self-registering reader module per archive format.

Importing this package is required: each submodule ends with ``register_reader(...)``,
so a bare ``import archivey.internal.backends`` fills the registry. Do not remove the
side-effect imports below.

Module map:

- :mod:`.zip_reader` — ZIP (stdlib central directory; codecs/crypto for member data)
- :mod:`.tar_reader` — TAR / compressed TAR (native :mod:`.tar_parser`)
- :mod:`.udif` — UDIF disk images (``.dmg``); recognised and refused, not read
- :mod:`.iso_reader` — ISO 9660 (``pycdlib``, ``[recommended]``)
- :mod:`.directory_reader` — filesystem directory as a pseudo-archive
- :mod:`.single_file_reader` — bare ``.gz`` / ``.xz`` / … as a one-member archive
- :mod:`.sevenzip_methods` / ``sevenzip_parser`` / ``sevenzip_pipeline`` /
  ``sevenzip_reader`` — native 7z (method registry → header parse → folder decode → ABC)
- :mod:`.rar_parser` / ``rar_unrar`` / ``rar_reader`` — native RAR metadata + ``unrar`` data;
  ``rar_unar`` — the RAR refusals and pipe layout for the opt-in ``unar`` data path

Format-specific helpers that are not readers live here too, next to the parser they share
logic with: the scan-hit validators :mod:`.zip_detect`, :mod:`.sevenzip_detect` and
:mod:`.rar_detect`, which the readers pass to ``internal/sfx.py``'s scan as ``HitValidator``
callbacks (the dependency runs from here to ``sfx.py``, never back; ``zip_detect`` also
carries the split-segment name check ``core.py`` uses), and the ZIP ciphers
:mod:`.zipcrypto` and :mod:`.zip_aes`. The axis is per format, not per phase: everything
that supports one format sits together so it can be read and kept in sync at once. Format-agnostic detection (``detection.py``, ``detection_workspace.py``, ``sfx.py``)
stays at the top of ``internal/``.

Typical split inside a format: ``*ReadBackend`` (registry / ``open_read``) +
``*Reader`` (``BaseArchiveReader``). Native 7z/RAR also split parse vs decode.
"""

from archivey.internal.backends import (
    directory_reader as _directory_reader,  # noqa: F401
    iso_reader as _iso_reader,  # noqa: F401
    rar_reader as _rar_reader,  # noqa: F401
    sevenzip_reader as _sevenzip_reader,  # noqa: F401
    single_file_reader as _single_file_reader,  # noqa: F401
    tar_reader as _tar_reader,  # noqa: F401
    udif as _udif,  # noqa: F401
    zip_reader as _zip_reader,  # noqa: F401
)
