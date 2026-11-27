"""``ArchiveyConfig(fallback_encoding=)``: one name-encoding fallback for every format.

The maintainer ruled on 2026-11-27 that the fallback lives in the config, for every
format, replacing both ``open_archive(encoding=)`` and the ZIP-only
``zip_unflagged_fallback_encoding``, which keep working through 0.6 with a
``DeprecationWarning``.
"""

from __future__ import annotations

import dataclasses
import io
import tarfile
import warnings
import zipfile

import pytest

import archivey
from archivey import ArchiveyConfig, ArchiveyUsageError


def _zip_with_name(raw: bytes) -> bytes:
    """A one-member ZIP whose name is ``raw``, stored without the UTF-8 flag."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("X" * len(raw), b"data")
    return buf.getvalue().replace(b"X" * len(raw), raw)


def _flagged_zip_with_name(raw: bytes) -> bytes:
    """A one-member ZIP whose name is ``raw``, stored with the UTF-8 flag set."""
    # A non-ASCII placeholder of the same byte length makes zipfile set the flag.
    placeholder = "X" * (len(raw) - 2) + "\u00e9"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(placeholder, b"data")
    return buf.getvalue().replace(placeholder.encode(), raw)


def _tar_with_name(raw: bytes) -> bytes:
    """A one-member ustar TAR whose name is ``raw``."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        info = tarfile.TarInfo("X" * len(raw))
        info.size = 4
        tf.addfile(info, io.BytesIO(b"data"))
    data = bytearray(buf.getvalue())
    data[: len(raw)] = raw
    # The header checksum covers the name: recompute it.
    data[148:156] = b" " * 8
    data[148:156] = b"%06o\0 " % sum(data[:512])
    return bytes(data)


_CP1252_NAME = "café.txt"
_RAW = _CP1252_NAME.encode("cp1252")  # 0xE9 alone: not valid UTF-8


def _names(data: bytes, **kwargs: object) -> list[str]:
    with archivey.open_archive(io.BytesIO(data), **kwargs) as reader:  # type: ignore[arg-type]
        return [m.name for m in reader.members()]


@pytest.mark.parametrize("build", [_zip_with_name, _tar_with_name], ids=["zip", "tar"])
def test_the_config_fallback_decodes_an_undeclared_name(build) -> None:
    config = ArchiveyConfig(fallback_encoding="cp1252")
    assert _names(build(_RAW), config=config) == [_CP1252_NAME]


def test_valid_utf8_wins_over_the_fallback() -> None:
    raw = _CP1252_NAME.encode("utf-8")
    config = ArchiveyConfig(fallback_encoding="cp1252")
    assert _names(_zip_with_name(raw), config=config) == [_CP1252_NAME]


def test_none_keeps_each_formats_own_fallback() -> None:
    assert _names(_zip_with_name(_RAW)) == [_RAW.decode("cp437")]
    assert _names(_tar_with_name(_RAW)) == [
        _RAW.decode("utf-8", errors="surrogateescape")
    ]


def test_a_nested_open_inherits_the_parents_fallback() -> None:
    inner = _tar_with_name(_RAW)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner.tar", inner)
    config = ArchiveyConfig(fallback_encoding="cp1252")
    source = io.BytesIO(buf.getvalue())
    with (
        archivey.open_archive(source, config=config, seekable_members=True) as outer,
        outer.open("inner.tar") as stream,
        archivey.open_archive(stream, parent=outer) as child,
    ):
        assert [m.name for m in child.members()] == [_CP1252_NAME]


def test_the_encoding_argument_warns_and_still_decides() -> None:
    with pytest.warns(DeprecationWarning, match="fallback_encoding") as caught:
        names = _names(_zip_with_name(_RAW), encoding="cp1252")
    assert names == [_CP1252_NAME]
    assert caught[0].filename == __file__


def test_the_encoding_argument_replaces_the_config_fallback() -> None:
    config = ArchiveyConfig(fallback_encoding="cp866")
    with pytest.warns(DeprecationWarning):
        names = _names(_zip_with_name(_RAW), encoding="cp1252", config=config)
    assert names == [_CP1252_NAME]


def test_the_zip_field_warns_and_moves_into_fallback_encoding() -> None:
    with pytest.warns(DeprecationWarning, match="fallback_encoding") as caught:
        config = ArchiveyConfig(zip_unflagged_fallback_encoding="cp1252")
    assert caught[0].filename == __file__
    assert config.fallback_encoding == "cp1252"
    assert config.zip_unflagged_fallback_encoding is None
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        copy = dataclasses.replace(config, fallback_encoding="cp866")
    assert copy.fallback_encoding == "cp866"


def test_the_zip_field_beside_a_different_fallback_is_refused() -> None:
    with (
        pytest.warns(DeprecationWarning),
        pytest.raises(ArchiveyUsageError, match="fallback_encoding"),
    ):
        ArchiveyConfig(
            zip_unflagged_fallback_encoding="cp1252", fallback_encoding="cp866"
        )


def test_an_unknown_codec_is_refused() -> None:
    with pytest.raises(ArchiveyUsageError, match="fallback_encoding"):
        ArchiveyConfig(fallback_encoding="no-such-codec")


def test_the_file_system_encoding_argument_warns(tmp_path) -> None:
    pytest.importorskip("fsspec")
    from archivey.fsspec import ArchiveyFileSystem

    path = tmp_path / "a.zip"
    path.write_bytes(_zip_with_name(_RAW))
    with pytest.warns(DeprecationWarning, match="fallback_encoding") as caught:
        fs = ArchiveyFileSystem(str(path), encoding="cp1252")
    try:
        assert caught[0].filename == __file__
        assert [m.name for m in fs.reader.members()] == [_CP1252_NAME]
    finally:
        fs.close()


def _ar_with_name(raw: bytes) -> bytes:
    """A one-member ``ar`` archive (System V names, ``/``-terminated) named ``raw``."""
    data = b"data"
    header = (
        (raw + b"/").ljust(16)
        + b"0".ljust(12)
        + b"0".ljust(6)
        + b"0".ljust(6)
        + b"100644".ljust(8)
        + str(len(data)).encode().ljust(10)
        + b"`\n"
    )
    return b"!<arch>\n" + header + data


def _rpm_with_name(raw: bytes) -> bytes:
    """An RPM whose one file is ``/opt/`` + ``raw``: its reader decodes the name with a
    ``.`` in front, so the bytes it decodes are not the bytes it stores."""
    from tests.test_rpm import _F, _build, _Package

    return _build(_Package([_F(b"/opt/" + raw, data=b"data")]))


def _xar_with_nested_name(raw: bytes) -> bytes:
    """A XAR with ``raw`` as a base64 name inside the directory ``d``: its reader
    decodes one component and stores the joined path."""
    import base64

    from tests.xar_util import XarFile, write_xar

    name = f'<name enctype="base64">{base64.b64encode(raw).decode()}</name>'
    inner = XarFile("", b"data", name_xml=name)
    return write_xar([XarFile("d", type="directory", children=[inner])])


_FALLBACK = archivey.DiagnosticCode.MEMBER_NAME_FALLBACK_ENCODING


def _fallbacks(data: bytes, **kwargs: object) -> list[str]:
    """The ``fallback_encoding`` each member's fallback report names, in order."""
    with archivey.open_archive(io.BytesIO(data), **kwargs) as reader:  # type: ignore[arg-type]
        return [
            d.context.fallback_encoding
            for m in reader.members()
            for d in m.diagnostics
            if d.code is _FALLBACK
        ]


@pytest.mark.parametrize(
    ("build", "own"),
    [
        (_zip_with_name, "cp437"),
        (_tar_with_name, "surrogateescape"),
        (_ar_with_name, "surrogateescape"),
        (_rpm_with_name, "surrogateescape"),
        (_xar_with_nested_name, "surrogateescape"),
    ],
    ids=["zip", "tar", "ar-through-decode_name", "rpm-prefixed", "xar-nested"],
)
def test_a_name_through_the_fallback_is_reported_with_its_codec(build, own) -> None:
    """Whichever fallback decoded it, the format's own or the caller's, the report is
    on the member and names the codec, since another setting could change the name."""
    assert _fallbacks(build(_RAW)) == [own]
    config = ArchiveyConfig(fallback_encoding="cp1252")
    assert _fallbacks(build(_RAW), config=config) == ["cp1252"]


@pytest.mark.parametrize(
    "build", [_zip_with_name, _tar_with_name, _ar_with_name], ids=["zip", "tar", "ar"]
)
def test_a_utf8_or_ascii_name_is_not_reported(build) -> None:
    config = ArchiveyConfig(fallback_encoding="cp1252")
    assert _fallbacks(build(_CP1252_NAME.encode("utf-8")), config=config) == []
    assert _fallbacks(build(b"plain.txt"), config=config) == []


def test_strict_does_not_refuse_a_legacy_name() -> None:
    """A code-page name is how DOS and Windows tools wrote archives, not damage."""
    strict = ArchiveyConfig(diagnostic_policy=archivey.DiagnosticPolicy.STRICT)
    assert _fallbacks(_zip_with_name(_RAW), config=strict) == ["cp437"]


def test_a_tar_inside_a_makeself_reports_a_name_once() -> None:
    """The nested TAR reader reports the name; the makeself listing adds no second
    report for the same member."""
    import gzip

    from tests.test_makeself import _with_payloads

    data = _with_payloads([gzip.compress(_tar_with_name(_RAW), mtime=0)])
    assert _fallbacks(data) == ["surrogateescape"]


_MISMATCH = archivey.DiagnosticCode.MEMBER_NAME_ENCODING_MISMATCH


def _codes(data: bytes, **kwargs: object) -> list[archivey.DiagnosticCode]:
    with archivey.open_archive(io.BytesIO(data), **kwargs) as reader:  # type: ignore[arg-type]
        return [d.code for m in reader.members() for d in m.diagnostics]


def test_a_utf8_flag_the_bytes_contradict_is_reported_and_strict_refuses() -> None:
    """The header claims UTF-8 and its bytes disprove it: damage, not a legacy
    code page, so STRICT refuses it, while the name still lists by default."""
    data = _flagged_zip_with_name(_RAW)
    codes = _codes(data)
    assert _MISMATCH in codes
    assert _FALLBACK in codes
    strict = ArchiveyConfig(diagnostic_policy=archivey.DiagnosticPolicy.STRICT)
    with pytest.raises(archivey.ArchiveyError):
        _codes(data, config=strict)


@pytest.mark.parametrize(
    "build", [_zip_with_name, _flagged_zip_with_name], ids=["unflagged", "flagged"]
)
def test_a_utf8_name_is_not_a_wrong_flag(build) -> None:
    """A UTF-8 name, flagged or not (macOS writes it unflagged), is not reported."""
    assert _MISMATCH not in _codes(build(_CP1252_NAME.encode("utf-8")))


def test_a_legacy_name_without_the_flag_is_not_a_wrong_flag() -> None:
    assert _MISMATCH not in _codes(_zip_with_name(_RAW))
