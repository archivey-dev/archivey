"""A damaged ``-hp`` archive listed with the empty password raises CorruptionError.

The fuzz input below holds plain RAR5 headers, then a crypt header with no password
check, so every candidate "decrypts" it, the empty one included. Reading a member then
needs the header password for ``unrar``. ``unrar`` takes the empty password as none, so
the reader kept no password, and an assertion that the listing must have had one
raised ``AssertionError``. The file is damaged, and no password can help, so the read
raises ``CorruptionError``, the same class a non-empty first candidate gets. Found by
the RAR fuzz target.
"""

from __future__ import annotations

import io

import pytest

from archivey import ArchiveFormat, ArchiveyError, CorruptionError, open_archive
from tests.conftest import requires, requires_binary

_INPUT = bytes.fromhex(
    "526172211a07010009efc86f0b0105070406010180808000dbe1b3ee2302030ba20004c806a4"
    "8302d8353b7c801b0105612e7478740a031358ced86aec0a9519c6831f33032fb2379c51da9a"
    "4ccc92641ff0d3911d577bdbcb572281b9a9671c7b8ad25d50e22302030b860004c806a48302"
    "ff9619c0851f43042fb22790a26c07b3d277a0bf0d2223b2f4f745b3105956c5bd1721040000"
    "010f64b117d42cf4e72c6abb2102030b08040ba483f594a22f106fd9087ae15e9a7dfab90a53"
    "74b3fd2cc15a69a00def4a350afa1fbd480400"
)


@requires_binary("unrar")
@requires("cryptography")
@pytest.mark.parametrize(
    "password",
    [["", "password"], "", b"", "password", ["password", ""]],
    ids=["empty-first", "empty", "empty-bytes", "nonempty", "nonempty-first"],
)
def test_reading_a_member_raises_corruption_whatever_the_candidate(
    password: str | bytes | list[str],
) -> None:
    with open_archive(
        io.BytesIO(_INPUT), format=ArchiveFormat.RAR, password=password
    ) as reader:
        member = next(iter(reader))
        assert member.is_file
        with pytest.raises(CorruptionError):
            reader.open(member).read()


@requires_binary("unrar")
def test_every_member_read_raises_an_archivey_error() -> None:
    # The fuzz target's own loop: list and read until the walk's error.
    with (
        pytest.raises(ArchiveyError),
        open_archive(
            io.BytesIO(_INPUT), format=ArchiveFormat.RAR, password=""
        ) as reader,
    ):
        for member in reader:
            if member.is_file:
                reader.open(member).read()
