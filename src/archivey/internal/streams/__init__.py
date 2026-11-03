"""Compressed + seekable stream layer used by format backends.

Backends never import codec libraries directly; they compose the pieces below
(see ``compressed-streams`` / ``seekable-decompressor-streams``).

Package map:

- :mod:`.streamtools` — codec-/format-agnostic ``BinaryIO`` plumbing (slice, lock,
  shared views, solid demux). Must not import the rest of archivey.
- :mod:`.codecs` — everything specific to one codec: ``Codec`` / ``StreamCodec`` /
  ``open_codec_stream`` (the uniform pull-based codec table + detection signals), each
  codec's ``<name>_codec`` descriptor, and its engine beside it (``<name>_decoder``,
  framing and resume helpers, the 7z branch filters, the PPMd and rapidgzip child
  processes).
- :mod:`.decompressor_stream` — seekable decode *engine* (``DecompressorStream`` +
  ``Decoder`` protocol) that the codec decoders plug into.
- :mod:`.child_process` — spawning and reaping the codec child processes.
- :mod:`.kept_errors` — keeping an error a stream raises again without its frames
  (shared by ``codecs`` and the streams above them).
- :mod:`.native_memory` — what PyPy's GC is told about in-process decoders' native
  buffers, and the liblzma end a decoder's close calls (shared by ``codecs`` and the
  engine, so it sits below both).
- :mod:`.archive_stream` — ``ArchiveStreamImpl``, the member/codec handle behind the
  public ``ArchiveStream``: exception translate+stamp, lazy open, nested collapse,
  fused digest verify, lease/finalizer.
- :mod:`.resume` — re-exports ``ask_resume_offset`` (rewind-cost query; the
  helper lives in ``streamtools.binaryio`` as generic ``getattr`` plumbing,
  named exception in that package's docstring).
- :mod:`.verify` — ``MemberVerifier`` (+ standalone ``VerifyingStream`` for codec
  length backstops).
- :mod:`.verification` — what each layer of a member stream has proved
  (``ask_verification_proofs``), for ``ArchiveStream.verified``.
- :mod:`.respawn` — ``RespawnStream``: seeks over a stream that only reads forward,
  reading through on a forward seek and reopening it on a backward one.
- :mod:`.blocks` — ``BlockStream``: a file stored as fixed-size blocks that each
  decode on their own, for ``archivey.formats.block_stream``.
- :mod:`.crypto` — AES decrypt stage (``[recommended]``) + 7z-local KDF helpers.
- :mod:`.counting` — measurement wrappers (bytes / seeks).
"""
