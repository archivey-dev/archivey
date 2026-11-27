"""Format backends — one self-registering reader module per archive format.

Importing this package is required: it registers every format of core's table
(``internal/format_table.py``), so a bare ``import archivey.internal.backends`` fills
the registry. The modules written against ``BaseArchiveReader`` register on import
(``register_reader(...)``); for those written against ``archivey.formats`` the table
names the handler, and the module does not register itself.

Module map. These are written against ``BaseArchiveReader`` and register with
``register_reader``. A reading backend usually has a ``*ReadBackend`` (registry /
``open_read``) and a ``*Reader``. The extra modules on a bullet
are that reader's helpers:

- :mod:`.zip_reader` / ``zip_parser`` — ZIP (native central-directory parser;
  codecs/crypto for member data); ``zip_local_walk`` / ``zip_forward_reader`` read a
  ZIP front to back from a source that cannot seek
- :mod:`.tar_reader` — TAR / compressed TAR (native :mod:`.tar_parser`)
- :mod:`.directory_reader` — filesystem directory as a pseudo-archive
- :mod:`.single_file_reader` — bare ``.gz`` / ``.xz`` / … as a one-member archive
- :mod:`.sevenzip_methods` / ``sevenzip_parser`` / ``sevenzip_pipeline`` /
  ``sevenzip_reader`` — native 7z (method registry → header parse → folder decode → ABC)
- :mod:`.rar_parser` / ``rar_unrar`` / ``rar_reader`` — native RAR metadata + ``unrar`` data;
  ``rar_unar`` — the RAR refusals and pipe layout for the opt-in ``unar`` data path

These are written against the public plugin API, ``archivey.formats``, as a format
added from outside would be: a ``*Handler`` declares the format and opens a
``*Reader``, and ``internal/format_adapter.py`` makes a backend of the handler:

- :mod:`.iso_reader` — ISO 9660, Joliet, Rock Ridge (:mod:`.iso9660`) and UDF
  (:mod:`.udf`)
- :mod:`.ar_reader` — Unix ar
- :mod:`.rpm_reader` — RPM packages (headers, then the CPIO payload)
- :mod:`.deb_reader` — Debian packages, an ar layer whose tars it reads through
  ``ReaderContext.open_nested``
- :mod:`.makeself_reader` — makeself ``.run`` installers (a shell header, then TARs)
- :mod:`.cpio_reader` — CPIO (binary, odc, newc, crc, afio)
- :mod:`.squashfs_reader` — SquashFS 4.0
- :mod:`.xar_reader` — XAR (``.xar``)
- :mod:`.pkg_reader` — macOS ``.pkg`` and ``.xip``: a XAR whose CPIO payloads it reads
  through ``ReaderContext.open_nested``
- :mod:`.cab_reader` — Microsoft cabinets (stored, MSZIP, LZX)
- :mod:`.lha_reader` — LHA (header levels 0-3; stored, ``-lh1-``, ``-lh4-`` to
  ``-lh7-``, ``-lhx-``, ``-lk7-``, ``-lzs-``, ``-lz5-``)
- :mod:`.arj_reader` — ARJ (methods 0 to 4)
- :mod:`.dmg_reader` — Apple disk images (``.dmg``): UDIF (:mod:`.udif`), the
  partition map (:mod:`.disk_partitions`), HFS+ volumes (:mod:`.hfsplus`) and APFS
  containers (:mod:`.apfs`)

Format-specific helpers that are not readers live here too, next to the parser they share
logic with: the scan-hit validators :mod:`.zip_detect`, :mod:`.sevenzip_detect` and
:mod:`.rar_detect`, which the readers pass to ``internal/sfx.py``'s scan as ``HitValidator``
callbacks (the dependency runs from here to ``sfx.py``, never back; ``zip_detect`` also
carries the split-segment name check ``core.py`` uses), and the ZIP ciphers
:mod:`.zipcrypto` and :mod:`.zip_aes`. The axis is per format, not per phase: everything
that supports one format sits together so it can be read and kept in sync at once.
Format-agnostic detection (``detection.py``, ``detection_workspace.py``, ``sfx.py``)
stays at the top of ``internal/``.

Native 7z and RAR also split parse from decode.
"""

from archivey.internal.format_table import register_core_formats

# Imports each reader module and registers its format, in the table's order.
register_core_formats()
