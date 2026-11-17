"""A member's source cut must fail even when synthetic padding matches its digest."""

from __future__ import annotations

import pytest

from archivey import ArchiveyConfig, SpoolLimits, TruncatedError, open_archive
from tests.conftest import requires_unrar_cli
from tests.test_audit_outside_rar_sweep_2026_11_15 import _rar5, _rar5_file
from tests.test_rar_forward import _pipe, rolling_unrar  # noqa: F401

# BLAKE2sp of 6 and 24 MiB of zeros. Hashing them in the test takes about a minute
# with the pure-Python hasher, past the per-test timeout.
_ZEROS_BLAKE2SP = {
    6: bytes.fromhex(
        "b878b13c60bac85d452f92d71b9ce5cae3cf606242db7c3a6fde70630aa9cedb"
    ),
    24: bytes.fromhex(
        "a83583bd897a0226f97faaf8f95b2bc718e343ce90d85d6ef1cccc13ea8cf681"
    ),
}


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
@pytest.mark.parametrize("blake2sp", [False, True], ids=["crc32", "blake2sp"])
@pytest.mark.parametrize(
    "limit", [2 << 20, None], ids=["small-volumes", "default-volumes"]
)
@pytest.mark.parametrize("read", ["all", "exact", "chunks", "readinto"])
def test_a_late_source_cut_fails_the_member_read(
    blake2sp: bool, limit: int | None, read: str
) -> None:
    # More than the 4 MiB source lookahead and one synthetic volume. The member is
    # listed before the feeder discovers its missing tail. That tail would be all
    # zeros, so a digest over synthetic padding alone cannot detect its absence.
    size, cut_at = (6, 5) if limit is not None else (24, 20)
    # Built by hand, as ``rar a -m0`` stores it: CI never installs the RAR writer.
    raw = _rar5(
        _rar5_file("before", b"intact prefix", blake2sp=blake2sp),
        _rar5_file(
            "zeros", bytes(size << 20), blake2sp=blake2sp and _ZEROS_BLAKE2SP[size]
        ),
    )[: cut_at << 20]
    config = ArchiveyConfig(spool_limits=SpoolLimits(max_bytes=limit))
    with (
        open_archive(_pipe(raw), streaming=True, config=config) as reader,
        reader.stream_members() as members,
    ):
        member, stream = next(members)
        assert member.name == "before"
        assert stream is not None
        assert stream.read() == b"intact prefix"
        member, stream = next(members)
        assert member.name == "zeros"
        assert member.size == size << 20
        assert stream is not None
        with pytest.raises(TruncatedError, match="cut short"):
            if read == "all":
                stream.read()
            elif read == "exact":
                stream.read(member.size)
            elif read == "chunks":
                while stream.read(64 << 10):
                    pass
            else:
                buffer = bytearray(64 << 10)
                while stream.readinto(buffer):
                    pass
