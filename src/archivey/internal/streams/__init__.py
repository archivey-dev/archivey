"""Compressed + seekable stream layer used by format backends.

Backends never import codec libraries directly; they compose the pieces below
(see ``compressed-streams`` / ``seekable-decompressor-streams``).

How a member stream is stacked, from the archive's bytes up to the object the caller
reads (a typical ZIP member; other formats leave out or reorder layers):

1. **The archive source.** The caller's file or stream, shared by every open member
   (``streamtools.SharedSource``), or behind a lock held across each seek and read
   (``streamtools.LockedStream``, for TAR and ISO).
2. **The member's extent.** A slice (``streamtools.SlicingStream``; a ``SharedView``
   over a ``SharedSource``) bounds every read and seek to the member's bytes.
3. **Decryption**, for an encrypted member (:mod:`.crypto`).
4. **Decompression.** A codec stream from :mod:`.codecs`, most often a
   :class:`~archivey.internal.streams.decompressor_stream.DecompressorStream`. It
   also does the seeking within the decoded bytes, from the seek points it knows.
5. **The public stream.** ``ArchiveStreamImpl`` (:mod:`.archive_stream`) translates
   errors, runs the member's length and digest checks (:mod:`.verify`), and reports
   what the layers below proved (:mod:`.verification`).

A compressed TAR swaps 2 and 4: one codec stream decodes the whole archive, and each
member is a slice of its output. A solid 7z folder or RAR block does the same through
``streamtools.SolidBlockReader``. A member stream that can only read forward (an
``unrar`` pipe) gets seeking from :mod:`.respawn`; a file stored as blocks that each
decode on their own, from :mod:`.blocks`.

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
- :mod:`.verify` — ``MemberVerifier`` (+ standalone ``VerifyingStream`` for checks
  that must sit below another wrapper).
- :mod:`.verification` — what each layer of a member stream has proved
  (``ask_verification_proofs``), for ``ArchiveStream.verified``.
- :mod:`.respawn` — ``RespawnStream``: seeks over a stream that only reads forward,
  reading through on a forward seek and reopening it on a backward one.
- :mod:`.blocks` — ``BlockStream``: a file stored as fixed-size blocks that each
  decode on their own, for ``archivey.formats.block_stream``.
- :mod:`.read_hints` — the span of the archive a plugin's view (or a decoder over
  one) reads, carried on the stream for the range hint archivey gives.
- :mod:`.crypto` — AES decrypt stages (``[recommended]``). Key derivation stays with
  each format's backend.
- :mod:`.counting` — measurement wrappers (bytes / seeks).
"""
