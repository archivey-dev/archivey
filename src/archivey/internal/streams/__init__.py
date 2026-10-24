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
- :mod:`.native_memory` — what PyPy's GC is told about in-process decoders' native
  buffers, and the liblzma end a decoder's close calls (shared by ``codecs`` and the
  engine, so it sits below both).
- :mod:`.archive_stream` — public member/codec handle: exception translate+stamp,
  lazy open, nested collapse, fused digest verify, lease/finalizer.
- :mod:`.resume` — re-exports ``ask_resume_offset`` (rewind-cost query; the
  helper lives in ``streamtools.binaryio`` as generic ``getattr`` plumbing,
  named exception in that package's docstring).
- :mod:`.verify` — ``MemberVerifier`` (+ standalone ``VerifyingStream`` for codec
  length backstops).
- :mod:`.verification` — what each layer of a member stream has proved
  (``ask_verification_proofs``), for ``ArchiveStream.verified``.
- :mod:`.crypto` — AES decrypt stage (``[recommended]``) + 7z-local KDF helpers.
- :mod:`.counting` — measurement wrappers (bytes / seeks).
"""
