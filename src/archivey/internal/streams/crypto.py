"""AES stages via the ``[recommended]`` extra (``cryptography`` package).

Format parsers must not import ``cryptography`` directly — only this module does
(the backend stays swappable). AES is a *pipeline stage* ahead of a decompressor
(e.g. AES → LZMA2 for an encrypted 7z folder).

Layers here:

- :class:`DecryptStage` / :func:`open_aes_decrypt_stage` — feed ciphertext chunks,
  get plaintext (used when composing inside a larger open).
- :class:`KeystreamStage` / :func:`open_aes_ctr_stage` — AES-CTR with the counter
  convention as a parameter (WinZip AE counts little-endian from 1). CTR is its own
  inverse, so one stage both encrypts and decrypts.
- :class:`AesDecryptStream` / :func:`open_aes_decrypt_stream` — pull ``BinaryIO``
  wrapper over a ciphertext source (7z member data: CBC, optional seek).
  RAR headers and WinZip AES keep their own pull streams; see the class
  docstring.

Key derivation is not here: each format derives its keys its own way, so the 7z KDF
and its coder-property parser live in :mod:`archivey.internal.backends.sevenzip_aes`,
beside RAR's in ``rar_parser`` and WinZip AES's in ``zip_aes``.
"""

from __future__ import annotations

import importlib.util
import io
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from typing import BinaryIO, Literal, Protocol

from archivey.exceptions import (
    PackageNotInstalledError,
    TruncatedError,
)
from archivey.internal.streams.resume import ask_resume_offset
from archivey.internal.streams.streamtools import (
    ReadOnlyIOStream,
    is_seekable,
    read_exact,
    resolve_seek,
    source_byte_size,
)
from archivey.types import MissingComponent, OptionalLibrary

# The package name surfaced to users, and the single install hint every AES raise site
# (here and in zip_aes) formats its message from.
CRYPTO_PACKAGE = OptionalLibrary.CRYPTOGRAPHY
CRYPTO_REQUIREMENT = MissingComponent(
    CRYPTO_PACKAGE, "pip install archivey[recommended]", ("aes",)
)

# AES block size (also the CBC IV length). 7z writers pad *plaintext* to this
# and store a full ciphertext block, so a well-formed pack stream is aligned.
AES_BLOCK_SIZE = 16


class _AesCbcTruncatedError(TruncatedError):
    """Short last AES-CBC ciphertext block; private origin tag for confirm.

    ``_password_for_folder`` remaps a decoder ``TruncatedError`` (PPMd
    "File is truncated" on wrong-key garbage) to ``EncryptionError`` so
    ``PasswordManager.attempt`` can try the next candidate. This subclass
    is the AES ``finalize`` site, and must *not* remap: a truncated pack
    with the correct password is not a wrong key. Callers catching
    ``TruncatedError`` are unaffected.
    """


@dataclass(frozen=True)
class AesParams:
    """Inputs to an AES-CBC decrypt stage: the derived key and the initialization vector."""

    key: bytes = field(repr=False)
    iv: bytes


class DecryptStage(Protocol):
    """A streaming decrypt transform: feed ciphertext, get plaintext; ``finalize`` flushes."""

    def update(self, data: bytes) -> bytes: ...
    def finalize(self) -> bytes: ...


@dataclass(frozen=True)
class AesCtrParams:
    """Inputs to an AES-CTR keystream stage: the key and the counter convention.

    The counter is the whole 16-byte block — there is no separate nonce. Block
    ``i`` of the keystream is ``AES(key, (initial_counter + i) mod 2**128)``
    encoded in ``counter_byteorder``. Formats disagree on the convention, so
    neither field has a default: WinZip AE counts ``"little"`` from ``1``;
    NIST SP 800-38A and ``cryptography``'s ``modes.CTR`` count ``"big"``.
    """

    key: bytes = field(repr=False)
    initial_counter: int
    counter_byteorder: Literal["little", "big"]


class KeystreamStage(Protocol):
    """A streaming XOR transform: ``process`` maps input to output of the same length.

    Calls may split the input anywhere; the output is the same as one call over
    the concatenation. There is nothing to flush.
    """

    def process(self, data: bytes) -> bytes: ...


class CryptoBackend(ABC):
    """Abstraction over a crypto library. The only thing format code may depend on."""

    name: str

    @abstractmethod
    def aes_cbc_decrypt_stage(self, params: AesParams) -> DecryptStage:
        """Create an AES-256-CBC decrypt stage for ``params``."""
        ...

    @abstractmethod
    def aes_ctr_keystream_stage(self, params: AesCtrParams) -> KeystreamStage:
        """Create an AES-CTR stage for ``params`` (see :class:`AesCtrParams`)."""
        ...


class _CryptographyDecryptStage:
    """AES-256-CBC decrypt stage backed by ``cryptography`` Cipher."""

    def __init__(self, params: AesParams) -> None:
        # Local import: format parsers never import cryptography; only this wrapper does.
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        if len(params.key) not in (16, 24, 32):
            raise ValueError(
                f"AES key must be 16, 24, or 32 bytes, got {len(params.key)}"
            )
        if len(params.iv) != AES_BLOCK_SIZE:
            raise ValueError(
                f"AES-CBC IV must be {AES_BLOCK_SIZE} bytes, got {len(params.iv)}"
            )
        cipher = Cipher(algorithms.AES(params.key), modes.CBC(params.iv))
        self._decryptor = cipher.decryptor()
        self._buf = bytearray()

    def update(self, data: bytes) -> bytes:
        if not data:
            return b""
        self._buf.extend(data)
        # Hold a partial trailing block until finalize; CBC cannot decrypt it alone.
        n = len(self._buf) - (len(self._buf) % AES_BLOCK_SIZE)
        if n == 0:
            return b""
        block = bytes(self._buf[:n])
        del self._buf[:n]
        return self._decryptor.update(block)

    def finalize(self) -> bytes:
        if self._buf:
            # AES-CBC cannot recover a truncated block: P_n = D_K(C_n) XOR C_{n-1},
            # so a mangled C_n makes all 16 output bytes pseudorandom. Zero-padding
            # and decrypting anyway produced a *longer* plaintext (53 ciphertext
            # bytes → 64 garbage-tailed plaintext) — backwards for truncation
            # detection. Well-formed 7z never hits this: the encoder zero-pads
            # *plaintext* (FilterCoder.cpp / py7zr ``AESCompressor.flush``) and
            # stores a full ciphertext block; pack_size is a multiple of
            # AES_BLOCK_SIZE. Writer pad is discarded by the AES coder's
            # unpack_size, not here.
            leftover = len(self._buf)
            # View not block-aligned. Header malformed vs short file is a
            # header check (sevenzip-aes-tail-key-check task 1.1), not a
            # leftover split here — see that change's design.md.
            raise _AesCbcTruncatedError(
                f"AES-CBC ciphertext ended mid-block ({leftover} leftover "
                "byte(s); a truncated block cannot be decrypted)"
            )
        return self._decryptor.finalize()


# Counter blocks are 128-bit; the counter wraps modulo this.
_CTR_MODULUS = 1 << 128


class _CryptographyCtrStage:
    """AES-CTR keystream stage backed by ``cryptography``'s ECB primitive.

    ``modes.CTR`` only counts big-endian, so the counter blocks are built here and
    encrypted in one ECB ``update`` per call. The XOR is one big-integer operation
    over the whole call, not a Python loop per byte. A call that ends mid-block
    keeps the unused keystream bytes for the next call.
    """

    def __init__(self, params: AesCtrParams) -> None:
        # Local import: format parsers never import cryptography; only this wrapper does.
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        if len(params.key) not in (16, 24, 32):
            raise ValueError(
                f"AES key must be 16, 24, or 32 bytes, got {len(params.key)}"
            )
        if not 0 <= params.initial_counter < _CTR_MODULUS:
            raise ValueError("AES-CTR initial_counter must fit in 128 bits")
        if params.counter_byteorder not in ("little", "big"):
            raise ValueError(
                f"AES-CTR counter_byteorder must be 'little' or 'big', "
                f"got {params.counter_byteorder!r}"
            )
        self._encryptor = Cipher(algorithms.AES(params.key), modes.ECB()).encryptor()
        self._byteorder: Literal["little", "big"] = params.counter_byteorder
        self._counter = params.initial_counter
        # Keystream left over from a call that ended mid-block (< AES_BLOCK_SIZE bytes).
        self._spare = b""

    def process(self, data: bytes) -> bytes:
        n = len(data)
        if n == 0:
            return b""
        keystream = self._spare
        if len(keystream) < n:
            nblocks = -(-(n - len(keystream)) // AES_BLOCK_SIZE)
            counter, order = self._counter, self._byteorder
            blocks = b"".join(
                ((counter + i) % _CTR_MODULUS).to_bytes(AES_BLOCK_SIZE, order)
                for i in range(nblocks)
            )
            self._counter = (counter + nblocks) % _CTR_MODULUS
            keystream += self._encryptor.update(blocks)
        self._spare = keystream[n:]
        mixed = int.from_bytes(data, "little") ^ int.from_bytes(keystream[:n], "little")
        return mixed.to_bytes(n, "little")


class _CryptographyBackend(CryptoBackend):
    name = CRYPTO_PACKAGE

    def aes_cbc_decrypt_stage(self, params: AesParams) -> DecryptStage:
        return _CryptographyDecryptStage(params)

    def aes_ctr_keystream_stage(self, params: AesCtrParams) -> KeystreamStage:
        return _CryptographyCtrStage(params)


def _crypto_available() -> bool:
    """Whether the crypto backend's package is importable.

    Wrapped in a function (rather than an import-time flag) so tests can simulate the
    package being absent by patching this symbol.
    """
    return importlib.util.find_spec(CRYPTO_PACKAGE) is not None


def get_crypto_backend() -> CryptoBackend:
    """Return the crypto backend, or raise ``PackageNotInstalledError`` naming ``cryptography``.

    This is the single entry point to crypto for the whole library; format parsers call it
    rather than importing any crypto library themselves.
    """
    if not _crypto_available():
        raise PackageNotInstalledError(
            CRYPTO_REQUIREMENT.message("AES decryption"), missing=(CRYPTO_REQUIREMENT,)
        )
    return _CryptographyBackend()


def open_aes_decrypt_stage(params: AesParams) -> DecryptStage:
    """Convenience: resolve the crypto backend and build an AES-CBC decrypt stage."""
    return get_crypto_backend().aes_cbc_decrypt_stage(params)


def open_aes_ctr_stage(params: AesCtrParams) -> KeystreamStage:
    """Convenience: resolve the crypto backend and build an AES-CTR keystream stage."""
    return get_crypto_backend().aes_ctr_keystream_stage(params)


class AesDecryptStream(ReadOnlyIOStream):
    """Pull ``BinaryIO`` that decrypts an underlying ciphertext stream via AES-CBC.

    This is the 7z member-data wrapper. CBC can restart at any block using the
    preceding ciphertext block as the IV, so when the ciphertext source is
    seekable this stream is too — that is what keeps ``seekable_members=True``
    on an encrypted 7z folder. ``tell`` is the **plaintext** offset.
    ``seekable()`` follows the ciphertext source. ``SEEK_END`` still needs a
    known ciphertext length (production ``SharedView`` / ``SlicingStream``
    expose ``.size``); an unsized seekable source raises
    ``io.UnsupportedOperation``. Mid-stream ``seek`` still works.

    Two AES-CBC pull streams share :class:`DecryptStage`.
    ``WinZipAesDecryptStream`` is CTR: it takes a :class:`KeystreamStage` from
    the same backend and keeps its own pull loop, because its ``read`` also
    feeds the HMAC and checks it at the end.

    Folding ``_HeaderDecryptStream`` in is blocked by the header walk, not by
    flags this class is missing:

    - ``tell()`` is archive offset for both arms. ``header_fd`` is either the
      raw handle or the decrypt stream; a second method does not help while
      the raw handle is the other arm.
    - The stream sits mid-file on the shared archive handle, unbounded.
      Without a ``length=`` bound it would treat the rest of the file as
      ciphertext and report seekable; seeking would reposition the archive.

    Ownership is ``owns_inner`` (both borrow). ``read`` already gathers short
    source reads. A short last ciphertext block raises ``TruncatedError``
    (the private ``_AesCbcTruncatedError`` subclass). ``size`` / ``SEEK_END``
    report the intact full-block length, so the two truncated lengths
    answer differently after ``SEEK_END``:

    - 53 ciphertext bytes: ``size`` is 48, ``SEEK_END`` lands at 48, a
      subsequent read is empty (cursor already at recoverable EOF).
    - 5 ciphertext bytes: ``size`` is 0, ``SEEK_END`` at origin is a
      no-op (``new_pos == _pos`` before the past-end branch), and the
      next read raises. Marking eof whenever ``new_pos >= size`` would
      silence that sub-block case.

    After a completing read raises, the intact prefix stays in ``_buf``
    and ``_eof`` stays false: catch and drain the buffered blocks. Only
    a read that reaches the truncated tail raises. This is this class's
    policy: ``_HeaderDecryptStream`` never calls ``finalize``, and
    WinZip AES does not use ``DecryptStage``.
    """

    def __init__(
        self,
        source: BinaryIO,
        params: AesParams,
        *,
        owns_inner: bool = False,
    ) -> None:
        super().__init__()
        self._source = source
        self._params = params
        self._owns_inner = owns_inner
        self._seekable = is_seekable(source)
        # Ciphertext origin of this wrapper. Seekable sources are positioned at
        # the first ciphertext byte (a 7z pack ``SharedView`` starts at 0 of the
        # view). Non-seekable sources have no origin to restore; seek is refused.
        self._cipher_start = source.tell() if self._seekable else 0
        self._stage: DecryptStage = open_aes_decrypt_stage(params)
        self._buf = bytearray()
        self._eof = False
        self._pos = 0

    def _raise_if_closed(self) -> None:
        if self.closed:
            raise ValueError("I/O operation on closed file.")

    def read(self, n: int = -1, /) -> bytes:
        self._raise_if_closed()
        if n == 0:
            return b""
        while not self._eof and (n < 0 or len(self._buf) < n):
            # Round the source ask up to a block so CBC does not withhold a
            # partial block (and so the ciphertext cursor is derivable as
            # ``_cipher_start + _pos + len(_buf)`` for a full-count source —
            # ADR 0014). A short non-empty source read leaves bytes in the
            # stage buffer and the identity does not hold.
            if n < 0:
                ask = 65536
            else:
                want = max(n - len(self._buf), 1)
                extra = want % AES_BLOCK_SIZE
                ask = want if extra == 0 else want + (AES_BLOCK_SIZE - extra)
            chunk = self._source.read(ask)
            if not chunk:
                self._buf.extend(self._stage.finalize())
                self._eof = True
                break
            self._buf.extend(self._stage.update(chunk))
        if n < 0:
            out = bytes(self._buf)
            self._buf.clear()
        else:
            out = bytes(self._buf[:n])
            del self._buf[:n]
        self._pos += len(out)
        return out

    def tell(self, /) -> int:
        self._raise_if_closed()
        return self._pos

    def seekable(self) -> bool:
        return self._seekable

    def nearest_resume_offset(self, target: int) -> int:
        """Plaintext offset the composed stack must restart from to reach ``target``.

        Block-aligned. The answer is at or before ``target``, often well
        before it. ``composed`` is where the inner's resume point forces the
        stack to restart; ``block_start`` is where this stream alone could.
        The answer is the earlier of the two — the stack restarts at
        whichever constraint is deeper. For an inner that answered above the
        offset it was asked, the ``min`` also caps the result at
        ``block_start <= target``. A caller that acts on it reads forward
        from the answer.
        """
        block_start = target - (target % AES_BLOCK_SIZE)
        iv_off = self._cipher_start + max(block_start - AES_BLOCK_SIZE, 0)
        resume = ask_resume_offset(self._source, iv_off)
        if resume is None:
            return block_start
        # Restart at plaintext block k iff the IV block at cs + 16(k-1) is
        # at or after the inner's resume. Smallest such k for k ≥ 1:
        # P = ceil(q / 16) * 16 + 16, q = resume - cipher_start.
        # Block 0 is the exception: its IV is the stream's explicit IV, so
        # q == 0 (inner can resume at or before cipher_start) yields 0.
        # The +16 shift must not move for q in 1..16 — that still needs the
        # IV block at cipher_start, which is behind the inner's resume.
        q = max(0, resume - self._cipher_start)
        if q == 0:
            composed = 0
        else:
            composed = -(-q // AES_BLOCK_SIZE) * AES_BLOCK_SIZE + AES_BLOCK_SIZE
        return max(0, min(block_start, composed))

    @property
    def size(self) -> int | None:
        """Padded plaintext length when the ciphertext length is cheaply knowable.

        fsspec-style ``size``. This is the CBC-block-aligned length, not the
        payload length: a truncated 53-byte ciphertext reports 48 (intact
        blocks only), and well-formed 7z still includes up to 15 bytes of
        writer pad. The AES coder's ``unpack_size`` (next coder's
        ``pack_size``) trims the pad one layer up — which is why
        ``_bound_rapidgzip_source`` prefers ``params.pack_size`` over this.
        """
        return self._plaintext_size()

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        self._raise_if_closed()
        if not self._seekable:
            raise io.UnsupportedOperation("seek")

        new_pos = resolve_seek(offset, whence, pos=self._pos, end=self._end_offset)
        if new_pos == self._pos:
            return self._pos

        # Already decrypted into the buffer: consume from there.
        buf_end = self._pos + len(self._buf)
        if self._pos < new_pos <= buf_end:
            del self._buf[: new_pos - self._pos]
            self._pos = new_pos
            return self._pos

        # Past known plaintext end. Python files allow tell() past EOF;
        # the next read is empty.
        size = self._plaintext_size()
        if size is not None and new_pos >= size:
            cipher_len = self._cipher_len()
            if cipher_len is not None:
                # Source at EOF so a caller inspecting it agrees; this stream
                # will not read it again (_eof, and restart re-seeks).
                self._source.seek(self._cipher_start + cipher_len)
            self._buf.clear()
            self._eof = True
            self._pos = new_pos
            return self._pos

        # CBC restart: ciphertext block ``block - 1`` is the IV for ``block``.
        block, intra = divmod(new_pos, AES_BLOCK_SIZE)
        if not self._restart_at_block(block):
            # Size unknown, and the previous ciphertext block is past EOF —
            # same as seek-past-end. ``_restart_at_block`` already marked EOF.
            self._pos = new_pos
            return self._pos
        self._pos = block * AES_BLOCK_SIZE
        if intra:
            skipped = self.read(intra)
            if len(skipped) < intra:
                self._pos = new_pos
        return self._pos

    def _end_offset(self) -> int:
        """Return the plaintext size, the target of ``seek(0, SEEK_END)``."""
        size = self._plaintext_size()
        if size is None:
            # Production sources are SharedView / SlicingStream, which
            # expose .size, so this branch is cold. Unsized SEEK_END would
            # read(-1) the whole plaintext into _buf and throw it away.
            raise io.UnsupportedOperation("SEEK_END requires a known ciphertext length")
        return size

    def _cipher_len(self) -> int | None:
        total = source_byte_size(self._source)
        if total is None:
            return None
        return max(0, total - self._cipher_start)

    def _plaintext_size(self) -> int | None:
        """Recoverable plaintext length: intact full ciphertext blocks only.

        A short last ciphertext block is not payload: ``finalize`` raises
        ``TruncatedError`` rather than decrypting it, so this is
        ``cipher_len - remainder``, not a round-up. ``size`` / ``SEEK_END``
        therefore describe the recoverable payload; reading into the truncated
        tail is what raises. This method does not raise: ``size`` is the
        accelerator bound ``_bound_rapidgzip_source`` falls back to when
        ``pack_size`` is unknown, and a raising ``size`` would make that
        unusable. Maintainer decision (davitf, 2026-09-16).
        """
        cipher_len = self._cipher_len()
        if cipher_len is None:
            return None
        return cipher_len - (cipher_len % AES_BLOCK_SIZE)

    def _restart_at_block(self, block: int) -> bool:
        """Recreate the CBC decryptor so plaintext block ``block`` is next.

        Returns False when the preceding ciphertext block is not there (past
        EOF). A spent ``DecryptStage`` cannot be reused after ``finalize``;
        every reposition builds a fresh one.
        """
        if block == 0:
            iv = self._params.iv
            self._source.seek(self._cipher_start)
        else:
            self._source.seek(self._cipher_start + (block - 1) * AES_BLOCK_SIZE)
            iv = read_exact(self._source, AES_BLOCK_SIZE)
            if len(iv) < AES_BLOCK_SIZE:
                self._buf.clear()
                self._eof = True
                return False
            # ``read_exact`` left the source at the start of ``block``.
        self._stage = open_aes_decrypt_stage(replace(self._params, iv=iv))
        self._buf.clear()
        self._eof = False
        return True

    def close(self) -> None:
        if not self.closed:
            try:
                if self._owns_inner:
                    self._source.close()
            finally:
                super().close()


def open_aes_decrypt_stream(
    source: BinaryIO,
    params: AesParams,
    *,
    owns_inner: bool = False,
) -> BinaryIO:
    """Wrap ``source`` in an AES-CBC decrypt stream using the shared crypto backend.

    ``owns_inner`` defaults to borrow, matching :class:`DecompressorStream` /
    :class:`~archivey.internal.streams.streamtools.slice.SlicingStream`. The 7z
    pack view underneath is a :class:`~archivey.internal.streams.streamtools.slice.SharedView`.
    """
    return AesDecryptStream(source, params, owns_inner=owns_inner)
