"""WinZip AES (AE-1 / AE-2) decryption for ZIP members.

Wire format (APPNOTE / WinZip AE-x)::

    [salt][pw_verify(2)][AES-CTR ciphertext][HMAC-SHA1(10)]

The member's ``compress_type`` is 99; extra field ``0x9901`` carries vendor version
(AE-1=1 / AE-2=2), strength (1/2/3 → 128/192/256), and the actual compression method.
Key material is PBKDF2-HMAC-SHA1(password, salt, 1000) → enc_key ‖ auth_key ‖ pw_verify.
CTR uses a little-endian counter starting at 1 (no nonce). HMAC covers ciphertext only.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO, NamedTuple

from archivey.exceptions import (
    CorruptionError,
    PackageNotInstalledError,
    TruncatedError,
)
from archivey.internal.password import wrong_password_error
from archivey.internal.streams.crypto import (
    CRYPTO_REQUIREMENT,
    AesCtrParams,
    KeystreamStage,
    _crypto_available,
    open_aes_ctr_stage,
)
from archivey.internal.streams.streamtools import (
    ReadOnlyIOStream,
    read_exact,
    resolve_seek,
)
from archivey.internal.streams.verification import VerificationProofs

# The wrong-password message of every ZIP decrypt path (ZipCrypto and WinZip AES), so
# the paths cannot drift apart.
ZIP_WRONG_PASSWORD_MSG = "Wrong password for this ZIP member"

# WinZip AES extra-field header id.
_AES_EXTRA_ID = 0x9901
_HMAC_LEN = 10
_PBKDF2_ITERS = 1000
#: What :class:`WinZipAesForwardStream` reads from its source at once. A caller that
#: sizes ``hold_back`` from how far its own reads run ahead adds this.
FORWARD_READ = 1 << 16


@dataclass(frozen=True)
class WinZipAesInfo:
    """Parsed AE-x parameters from extra field ``0x9901``."""

    vendor_version: int  # 1 = AE-1, 2 = AE-2
    strength: int  # 1 / 2 / 3 → 128 / 192 / 256 bits
    actual_method: int  # underlying ZIP compression method id

    @property
    def key_bits(self) -> int:
        return {1: 128, 2: 192, 3: 256}[self.strength]

    @property
    def key_len(self) -> int:
        return self.key_bits // 8

    @property
    def salt_len(self) -> int:
        return self.key_bits // 16

    @property
    def is_ae2(self) -> bool:
        return self.vendor_version == 2


_FIELD_HEADER = struct.Struct("<HH")
_new_tuple = tuple.__new__


class ExtraField(NamedTuple):
    # Also built positionally (split_extra_fields); test_zip_aes pins this order.
    tag: int
    data: bytes
    complete: bool  # False: the declared size ran past the end of the blob


def iter_extra_fields(extra: bytes) -> Iterator[ExtraField]:
    """Yield each field of a ZIP extra-field blob lazily, as
    :func:`split_extra_fields` returns them.

    For callers that stop at the first match (the ZIP64 and AES probes): a blob can
    hold 16 000 fields, and splitting all of them to find the first costs thousands of
    times more. ``test_zip_aes`` checks that the two walks agree.
    """
    end_of_blob = len(extra)
    pos = 0
    while pos + 4 <= end_of_blob:
        tag, size = _FIELD_HEADER.unpack_from(extra, pos)
        start = pos + 4
        pos = start + size
        yield ExtraField(tag, extra[start:pos], pos <= end_of_blob)


def split_extra_fields(extra: bytes) -> tuple[ExtraField, ...]:
    """Every field of a ZIP extra-field blob, AES or not.

    It is the walk every ZIP extra-field parser that reads all the fields uses;
    :func:`iter_extra_fields` is its lazy twin for callers that stop early. Both live
    here rather than in ``zip_reader`` because ``zip_reader`` imports this module, so
    the reverse import would be a cycle. The listing splits a member's blob once and
    reads the fields for its name, times, owner and leftovers.

    A last field whose declared size runs past the blob comes back with the bytes
    that are there and ``complete`` false; each caller decides what that means (the
    Unicode Path field reports it as malformed). Trailing bytes too short for a header
    are ignored.
    """
    if not extra:
        return ()
    fields: list[ExtraField] = []
    end_of_blob = len(extra)
    pos = 0
    while pos + 4 <= end_of_blob:
        tag, size = _FIELD_HEADER.unpack_from(extra, pos)
        start = pos + 4
        pos = start + size
        # tuple.__new__ directly: the NamedTuple constructor adds a Python call. The
        # order is ExtraField's, pinned by test_zip_aes.
        fields.append(
            _new_tuple(  # pyrefly: ignore[bad-specialization]  # a NamedTuple is a tuple
                ExtraField, (tag, extra[start:pos], pos <= end_of_blob)
            )
        )
    return tuple(fields)


def aes_record_differences(
    local: WinZipAesInfo | None, central: WinZipAesInfo | None
) -> list[str]:
    """How a member's local WinZip AES record differs from its central one: empty
    when the two are equal, else one item per differing field, each "local against
    central" (:func:`local_first` words the order), or the side that holds no valid
    record. Unequal records always give at least one item.

    Every field decides what a read yields: the version whether the CRC is checked,
    the strength the key and salt lengths, the method the codec. A file read decodes
    by the central record and the forward pass by the local one, so any difference
    refuses the member on both (``ZipReader._with_local_method``,
    ``_header_disagreements``).
    """
    if local == central:
        return []
    if local is None:
        return ["the local header holds no valid WinZip AES record"]
    if central is None:
        return ["the directory holds no valid WinZip AES record"]
    differ = []
    if local.vendor_version != central.vendor_version:
        differ.append(f"AE-{local.vendor_version} against AE-{central.vendor_version}")
    if local.strength != central.strength:
        differ.append(f"AES key strength {local.strength} against {central.strength}")
    if local.actual_method != central.actual_method:
        differ.append(
            f"AES compression method {local.actual_method} against "
            f"{central.actual_method}"
        )
    if not differ:
        # Unequal records whose compared fields all match: a field added to
        # WinZipAesInfo and not compared above. Still a difference, so both reads
        # still refuse; test_zip_aes pins the fields compared.
        differ.append("the WinZip AES records differ")
    return differ


def local_first(differ: list[str]) -> str:
    """The suffix that says which side of an "X against Y" item is the local
    header's, for a message listing ``differ``; empty when no item is a pair."""
    return ", local first" if any(" against " in item for item in differ) else ""


def parse_winzip_aes_extra(extra: bytes) -> WinZipAesInfo | None:
    """Return AE info from a ZIP extra field blob, or ``None`` when absent/malformed."""
    for field in iter_extra_fields(extra):
        if not field.complete:
            break
        if field.tag == _AES_EXTRA_ID and len(field.data) >= 7:
            vendor_version, vendor_id, strength, actual_method = struct.unpack(
                "<H2sBH", field.data[:7]
            )
            if vendor_id != b"AE" or strength not in (1, 2, 3):
                return None
            if vendor_version not in (1, 2):
                return None
            return WinZipAesInfo(vendor_version, strength, actual_method)
    return None


def derive_winzip_aes_keys(
    password: bytes, *, salt: bytes, key_len: int
) -> tuple[bytes, bytes, bytes]:
    """PBKDF2-HMAC-SHA1 → ``(enc_key, auth_key, pw_verify)``."""
    derived = hashlib.pbkdf2_hmac(
        "sha1", password, salt, _PBKDF2_ITERS, dklen=key_len * 2 + 2
    )
    enc_key = derived[:key_len]
    auth_key = derived[key_len : key_len * 2]
    pw_verify = derived[key_len * 2 :]
    return enc_key, auth_key, pw_verify


def _mac_mismatch() -> CorruptionError:
    return CorruptionError(
        "WinZip AES HMAC mismatch (wrong password or tampered ciphertext)"
    )


class WinZipAesDecryptStream(ReadOnlyIOStream):
    """Decrypt an AE ciphertext body and verify the trailing HMAC-SHA1(10).

    ``source`` must be positioned at the start of the ciphertext (after salt +
    pw_verify) and bounded to ``cipher_len + 10`` (ciphertext + MAC). The HMAC is
    checked by the read that returns the last plaintext byte, before it returns.
    ``close`` is teardown only — it does not drain or authenticate (ADR 0014).

    Positions are plaintext offsets, equal to ciphertext offsets: CTR adds no bytes.
    Seeking needs a seekable ``source``. CTR decrypts from any offset (the counter
    for byte ``p`` is ``1 + p // 16``). The HMAC covers the ciphertext, not the
    plaintext, so a seek does not give it up: the HMAC takes in ciphertext only while
    reads continue its hashed prefix, and the read that reaches the end re-reads the
    rest of the ciphertext from ``source`` to complete it. That costs one sequential
    read of the unhashed ciphertext and no decryption. Seek positions follow
    :class:`~archivey.internal.streams.streamtools.SlicingStream` (and ``BytesIO``):
    only a negative ``SEEK_SET`` raises, a relative seek below 0 clamps to 0, and a
    seek past the end returns the requested position, where reads return ``b""``.

    Not :class:`~archivey.internal.streams.crypto.AesDecryptStream` (7z CBC). Close
    always owns ``source`` — the ZIP member payload slice has no borrow caller, so
    there is no ``owns_inner``.
    """

    def __init__(
        self,
        source: BinaryIO,
        *,
        enc_key: bytes,
        auth_key: bytes,
        cipher_len: int,
    ) -> None:
        super().__init__()
        # First: close() reads it, and IOBase.__del__ runs close() on a refused instance.
        self._source = source
        if cipher_len < 0:
            raise ValueError("cipher_len must be non-negative")
        if not _crypto_available():
            raise PackageNotInstalledError(
                CRYPTO_REQUIREMENT.message("WinZip AES decryption")
            )
        self._enc_key = enc_key
        self._ctr = self._ctr_stage_at(0)
        self._hmac = hmac.new(auth_key, digestmod=hashlib.sha1)
        self._hashed = 0  # length of the ciphertext prefix the HMAC has taken in
        self._authenticated = False
        self._mac_failed = False
        self._mac_matched = False
        self._cipher_len = cipher_len
        # The plaintext length, exactly (CTR adds no bytes). ``source_byte_size`` reads
        # it, so the codec layer's accelerator threshold and source bound see the true
        # input size of a member decoded from this stage.
        self.size = cipher_len
        self._cipher_remaining = cipher_len
        self._origin = source.tell() if source.seekable() else 0
        self._buf = bytearray()
        self._overshoot = 0  # how far a seek put the position past the ciphertext end

    def _ctr_stage_at(self, offset: int) -> KeystreamStage:
        # WinZip AE: the whole 16-byte counter block, little-endian, starting at 1.
        block, into = divmod(offset, 16)
        stage = open_aes_ctr_stage(
            AesCtrParams(
                self._enc_key, initial_counter=1 + block, counter_byteorder="little"
            )
        )
        if into:
            stage.process(bytes(into))  # discard the keystream before ``offset``
        return stage

    def _pull(self) -> None:
        """Decrypt the next chunk; at the ciphertext end, authenticate instead."""
        if self._cipher_remaining > 0:
            at = self._cipher_len - self._cipher_remaining
            chunk = self._source.read(min(65536, self._cipher_remaining))
            if not chunk:
                raise TruncatedError("Truncated WinZip AES ciphertext before HMAC")
            self._cipher_remaining -= len(chunk)
            if at <= self._hashed < at + len(chunk):
                # Extend the hashed prefix by whatever of this chunk continues it.
                self._hmac.update(chunk[self._hashed - at :])
                self._hashed = at + len(chunk)
            self._buf.extend(self._ctr.process(chunk))
            return
        self._authenticate()

    def _authenticate(self) -> None:
        """Complete the HMAC over the whole ciphertext and compare it with the MAC.

        Runs once, from a read at the ciphertext end. The source is then at the MAC.
        When seeks left part of the ciphertext unhashed, that part is read from the
        source again first; the source ends at the MAC either way.
        """
        if self._authenticated:
            return
        if self._hashed < self._cipher_len:
            self._source.seek(self._origin + self._hashed)
            while self._hashed < self._cipher_len:
                chunk = self._source.read(min(65536, self._cipher_len - self._hashed))
                if not chunk:
                    raise TruncatedError("Truncated WinZip AES ciphertext before HMAC")
                self._hmac.update(chunk)
                self._hashed += len(chunk)
        mac = read_exact(self._source, _HMAC_LEN)
        if len(mac) != _HMAC_LEN:
            raise TruncatedError("Truncated WinZip AES HMAC")
        self._authenticated = True
        expected = self._hmac.digest()[:_HMAC_LEN]
        if not hmac.compare_digest(mac, expected):
            # Every later read raises too: the last chunk it withheld stays withheld.
            self._mac_failed = True
            raise _mac_mismatch()
        self._mac_matched = True

    def _verification_proofs(self) -> VerificationProofs:
        # The HMAC covers the whole ciphertext, so its match covers every byte decoded
        # from it, below any codec. The source is ciphertext: nothing below counts.
        return VerificationProofs(content=self._mac_matched, content_possible=True)

    def read(self, size: int | None = -1) -> bytes:
        if size is None:  # read to EOF, as on any ``io`` stream
            size = -1
        # Past the end nothing is left to read, and a position the caller seeked
        # past the end is not a read that reached it: no verdict there.
        if size == 0 or self._overshoot:
            return b""
        if self._mac_failed:
            raise _mac_mismatch()
        while size < 0 or len(self._buf) < size:
            if self._cipher_remaining <= 0 and self._authenticated:
                break
            before = len(self._buf)
            self._pull()
            if len(self._buf) == before and self._cipher_remaining <= 0:
                break
        if size < 0:
            out = bytes(self._buf)
            self._buf.clear()
        else:
            out = bytes(self._buf[:size])
            del self._buf[:size]
        if out and not self._buf and self._cipher_remaining <= 0:
            # This read hands out the last plaintext byte: authenticate before it
            # returns, so a consumer that knows the size and never reads past it
            # still gets the verdict (and a mismatch withholds the last chunk).
            self._authenticate()
        return out

    def seekable(self) -> bool:
        return self._source.seekable()

    def tell(self) -> int:
        return (
            self._cipher_len - self._cipher_remaining - len(self._buf) + self._overshoot
        )

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        pos = self.tell()
        target = resolve_seek(offset, whence, pos=pos, end=lambda: self._cipher_len)
        if target == pos:
            return pos
        reach = min(target, self._cipher_len)
        self._source.seek(self._origin + reach)
        self._buf.clear()
        self._cipher_remaining = self._cipher_len - reach
        self._ctr = self._ctr_stage_at(reach)
        self._overshoot = target - reach
        return target

    def close(self) -> None:
        if self.closed:
            return
        try:
            # Do not drain remaining ciphertext for HMAC: close is teardown,
            # not a verdict (ADR 0014).
            self._source.close()
        finally:
            super().close()


class WinZipAesForwardStream(ReadOnlyIOStream):
    """Decrypt an AE ciphertext whose length is not known up front, read forward once.

    A bit-3 member's sizes come after its data, so where the ciphertext ends is
    learned only at the end, in one of two ways:

    - ``hold_back=None``: ``source`` ends where the member's data ends (a STORED
      member's descriptor scan found it). The last 10 bytes are the HMAC, so the
      stream holds back 10 and authenticates when ``source`` ends, before the read
      that returns ``b""``.
    - ``hold_back=n``: ``source`` runs on past the data (a codec member, whose codec
      finds its own end). Everything is decrypted as it is read, and the last ``n``
      bytes read are kept out of the HMAC until :meth:`authenticate_end` says where
      the data ended. ``n`` must cover how far past the end the codec's layers can
      have read.

    ``source`` must be positioned at the start of the ciphertext. Close owns it.
    """

    def __init__(
        self,
        source: BinaryIO,
        *,
        enc_key: bytes,
        auth_key: bytes,
        header_len: int,
        hold_back: int | None,
        read_ahead: bytes = b"",
    ) -> None:
        # First: close() reads it, and IOBase.__del__ runs close() on a refused instance.
        self._source = source
        super().__init__()
        if not _crypto_available():
            raise PackageNotInstalledError(
                CRYPTO_REQUIREMENT.message("WinZip AES decryption")
            )
        self._ctr = open_aes_ctr_stage(
            AesCtrParams(enc_key, initial_counter=1, counter_byteorder="little")
        )
        self._hmac = hmac.new(auth_key, digestmod=hashlib.sha1)
        self._header_len = header_len
        self._ends_with_data = hold_back is None
        self._hold_back = _HMAC_LEN if hold_back is None else hold_back
        # Bytes read from ``source`` and not yet in the HMAC: the last ones read.
        # ``read_ahead`` is ciphertext the opener read past the header.
        self._held = bytearray(read_ahead)
        # Ciphertext bytes read from ``source``, MAC and beyond included.
        self._read = len(read_ahead)
        self._buf = bytearray()
        self._ended = False
        self._mac_failed = False
        self._mac_matched = False

    def _pull(self) -> None:
        chunk = self._source.read(FORWARD_READ)
        if not chunk:
            self._ended = True
            if self._ends_with_data:
                self._check_mac(bytes(self._held))
            return
        self._read += len(chunk)
        if not self._ends_with_data:
            self._buf += self._ctr.process(chunk)
        held = self._held
        held += chunk
        over = len(held) - self._hold_back
        if over > 0:
            self._hmac.update(held[:over])
            if self._ends_with_data:
                self._buf += self._ctr.process(bytes(held[:over]))
            del held[:over]

    def _check_mac(self, mac: bytes) -> None:
        if not hmac.compare_digest(mac, self._hmac.digest()[:_HMAC_LEN]):
            # Every later read raises too: the last chunk it withheld stays withheld.
            self._mac_failed = True
            raise _mac_mismatch()
        self._mac_matched = True

    def _verification_proofs(self) -> VerificationProofs:
        # The HMAC covers the whole ciphertext, so its match covers every byte decoded
        # from it, below any codec. The source is ciphertext: nothing below counts.
        return VerificationProofs(content=self._mac_matched, content_possible=True)

    def readall(self) -> bytes:
        # Through ``read(-1)``, so a ``hold_back`` stream refuses it too.
        return self.read(-1)

    def authenticate_end(self, data_len: int, passed_over: bytes) -> None:
        """Authenticate a ``hold_back`` stream once the data's end is known.

        ``data_len`` is the member's whole data length (its descriptor's compressed
        size, salt to MAC); ``passed_over`` the data's bytes after those this stream
        read, which the end's search read instead. Raises ``CorruptionError`` on a
        data length too short for the envelope or a code that does not match.
        """
        assert not self._ends_with_data, (
            "a stream that ends with its data checks itself"
        )
        cipher_len = data_len - self._header_len - _HMAC_LEN
        if cipher_len < 0:
            raise CorruptionError(
                "WinZip AES member too short for salt/verify/HMAC "
                f"({data_len} < {self._header_len + _HMAC_LEN})"
            )
        hashed = self._read - len(self._held)
        # The codec's layers read at most ``hold_back`` past the data's end.
        assert hashed <= cipher_len, "hold_back covers how far the codec read ahead"
        rest = bytes(self._held) + passed_over
        self._hmac.update(rest[: cipher_len - hashed])
        self._check_mac(rest[cipher_len - hashed : cipher_len - hashed + _HMAC_LEN])

    def read(self, size: int | None = -1) -> bytes:
        if size is None:
            size = -1
        if size < 0 and not self._ends_with_data:
            # As the walk's codec data refuses it: the source runs on past the data.
            raise ValueError(
                "a codec member's ciphertext has no known end; read it in pieces"
            )
        if size == 0:
            return b""
        if self._mac_failed:
            raise _mac_mismatch()
        while (size < 0 or len(self._buf) < size) and not self._ended:
            self._pull()
        if size < 0:
            out = bytes(self._buf)
            self._buf.clear()
        else:
            out = bytes(self._buf[:size])
            del self._buf[:size]
        return out

    def close(self) -> None:
        if self.closed:
            return
        try:
            self._source.close()
        finally:
            super().close()


def open_winzip_aes_forward(
    raw: BinaryIO, *, aes: WinZipAesInfo, password: bytes, hold_back: int | None
) -> WinZipAesForwardStream:
    """Like :func:`open_winzip_aes_member`, for data whose size is not known up front
    (see :class:`WinZipAesForwardStream` for ``hold_back``).

    A ``hold_back=None`` source ends with the member's data, so the code's length is
    read with the header: a member too short for both is refused before the password
    is checked (``CorruptionError``), as the sized read refuses it. A ``hold_back``
    source that ends inside the header was cut (``TruncatedError``). The order is
    :func:`open_winzip_aes_member`'s: the impossible member before the availability
    gate (no library reads it), the cut source after it.
    """
    header_len = aes.salt_len + 2
    overhead = header_len + _HMAC_LEN
    head = read_exact(raw, overhead if hold_back is None else header_len)
    if hold_back is None and len(head) < overhead:
        raise CorruptionError(
            f"WinZip AES member too short for salt/verify/HMAC ({len(head)} < {overhead})"
        )
    if not _crypto_available():
        raise PackageNotInstalledError(
            CRYPTO_REQUIREMENT.message("WinZip AES decryption")
        )
    if len(head) < header_len:
        raise TruncatedError("Truncated WinZip AES salt or password-verification value")
    salt, stored_verify = head[: aes.salt_len], head[aes.salt_len : header_len]
    enc_key, auth_key, pw_verify = derive_winzip_aes_keys(
        password, salt=salt, key_len=aes.key_len
    )
    if not hmac.compare_digest(stored_verify, pw_verify):
        raise wrong_password_error(ZIP_WRONG_PASSWORD_MSG)
    return WinZipAesForwardStream(
        raw,
        enc_key=enc_key,
        auth_key=auth_key,
        header_len=header_len,
        hold_back=hold_back,
        read_ahead=head[header_len:],
    )


def open_winzip_aes_member(
    raw: BinaryIO,
    *,
    aes: WinZipAesInfo,
    password: bytes,
    compress_size: int,
) -> BinaryIO:
    """Peel salt/pw_verify from ``raw``, verify the password, return a decrypt stream.

    ``raw`` is the full member payload (salt + verify + ciphertext + HMAC) of length
    ``compress_size``. Raises ``EncryptionError`` on a wrong password (fast-fail on the
    2-byte verification value) and ``PackageNotInstalledError`` when ``cryptography``
    (the ``[recommended]`` extra) is absent, unless the header is impossible.
    """
    salt_len = aes.salt_len
    overhead = salt_len + 2 + _HMAC_LEN
    # A declared size too small for the envelope is an impossible header, not a short
    # read, so it stays CorruptionError; the four short reads below are TruncatedError.
    # It runs before the availability gate: no library can read such a member, so the
    # error type does not depend on the install (DR-5).
    if compress_size < overhead:
        raise CorruptionError(
            f"WinZip AES member too short for salt/verify/HMAC ({compress_size} < {overhead})"
        )
    if not _crypto_available():
        raise PackageNotInstalledError(
            CRYPTO_REQUIREMENT.message("WinZip AES decryption")
        )
    salt = read_exact(raw, salt_len)
    if len(salt) != salt_len:
        raise TruncatedError("Truncated WinZip AES salt")
    stored_verify = read_exact(raw, 2)
    if len(stored_verify) != 2:
        raise TruncatedError("Truncated WinZip AES password-verification value")

    enc_key, auth_key, pw_verify = derive_winzip_aes_keys(
        password, salt=salt, key_len=aes.key_len
    )
    if not hmac.compare_digest(stored_verify, pw_verify):
        raise wrong_password_error(ZIP_WRONG_PASSWORD_MSG)

    cipher_len = compress_size - overhead
    return WinZipAesDecryptStream(
        raw, enc_key=enc_key, auth_key=auth_key, cipher_len=cipher_len
    )
