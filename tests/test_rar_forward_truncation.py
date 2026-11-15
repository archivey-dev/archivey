"""A member's source cut must fail even when synthetic padding matches its digest."""

from __future__ import annotations

from pathlib import Path

import pytest

from archivey import ArchiveyConfig, SpoolLimits, TruncatedError, open_archive
from tests.conftest import requires_binary, requires_unrar_cli
from tests.test_rar_forward import _pipe, _rar, rolling_unrar  # noqa: F401


@requires_binary("rar")
@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
@pytest.mark.parametrize("hash_switch", ["-htc", "-htb"], ids=["crc32", "blake2sp"])
@pytest.mark.parametrize(
    "limit", [2 << 20, None], ids=["small-volumes", "default-volumes"]
)
@pytest.mark.parametrize("read", ["all", "exact", "chunks", "readinto"])
def test_a_late_source_cut_fails_the_member_read(
    tmp_path: Path, hash_switch: str, limit: int | None, read: str
) -> None:
    # More than the 4 MiB source lookahead and one synthetic volume. The member is
    # listed before the feeder discovers its missing tail. That tail would be all
    # zeros, so a digest over synthetic padding alone cannot detect its absence.
    size, cut_at = (6, 5) if limit is not None else (24, 20)
    raw = _rar(
        tmp_path,
        {"before": b"intact prefix", "zeros": bytes(size << 20)},
        "-cfg-",
        "-m0",
        "-ds",
        hash_switch,
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
