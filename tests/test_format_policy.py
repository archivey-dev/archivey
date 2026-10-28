"""``FormatPolicy``: which formats one open may use (``ArchiveyConfig.formats``).

Built-in formats are detected as always and refused after detection; a plugin format
the policy turns off is left out of detection. The plugin formats here are TOYA
variants from ``tests/test_plugins.py``.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from archivey import (
    DEFAULT_ARCHIVEY_CONFIG,
    ArchiveFormat,
    ArchiveMember,
    ArchiveyConfig,
    ArchiveyUsageError,
    ContainerFormat,
    FormatDetectionError,
    FormatPolicy,
    MemberType,
    PackageNotInstalledError,
    StreamFormat,
    StreamNotSeekableError,
    UnsupportedFeatureError,
    detect_format,
    open_archive,
    open_stream,
)
from archivey.detection_cost import TierSkipReason
from archivey.internal.detection import probe_config
from archivey.internal.plugin_adapter import registration_scope
from archivey.plugins import (
    FormatPlugin,
    IndexedReader,
    Magic,
    MemberData,
    MemberRecord,
    PluginContext,
    PluginSource,
    SequentialFormatPlugin,
    SequentialReader,
)
from tests.test_plugins import _ENTRIES, _MAGIC, _plugin_with, build_toya
from tests.test_sfx import _pe_stub

C = ContainerFormat
S = StreamFormat


@pytest.fixture
def clean_registry() -> Iterator[None]:
    with registration_scope():
        yield


def _config(**kwargs: object) -> ArchiveyConfig:
    return ArchiveyConfig(formats=FormatPolicy(**kwargs))  # type: ignore[arg-type]


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"alpha")
    return buf.getvalue()


def _tar_gz_bytes() -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = 5
        tf.addfile(info, io.BytesIO(b"alpha"))
    return gzip.compress(raw.getvalue())


# --- construction ---------------------------------------------------------------


def test_the_default_policy_allows_every_format() -> None:
    policy = FormatPolicy()
    for fmt in (ArchiveFormat.ZIP, ArchiveFormat.TAR_GZ, ArchiveFormat.DIRECTORY):
        assert policy.allows(fmt)
    assert ArchiveyConfig().formats == policy


def test_arguments_are_stored_as_frozensets() -> None:
    policy = FormatPolicy(only=[C.ZIP, S.GZIP], exclude=(C.RAR,))
    assert policy.only == frozenset({C.ZIP, S.GZIP})
    assert policy.exclude == frozenset({C.RAR})


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"only": {C.UNKNOWN}}, "names no format"),
        ({"exclude": {S.UNCOMPRESSED}}, "UNCOMPRESSED in exclude"),
        ({"only": {C.ZIP}, "exclude": {C.ZIP}}, "both only= and exclude="),
        ({"only": {ArchiveFormat.TAR_GZ}}, "ContainerFormat.TAR"),
        ({"only": {"zip"}}, "got 'zip'"),
        ({"only": "zip"}, "collection"),
        ({"exclude": None}, "collection"),
        ({"plugins": "no"}, "plugins="),
    ],
)
def test_construction_refusals(kwargs: dict[str, object], match: str) -> None:
    with pytest.raises(ArchiveyUsageError, match=match):
        FormatPolicy(**kwargs)  # type: ignore[arg-type]


def test_a_listed_plugin_container_with_plugins_off_is_refused(
    clean_registry: None,
) -> None:
    plugin = _plugin_with("listed")
    with pytest.raises(ArchiveyUsageError, match="plugins=False"):
        FormatPolicy(only={plugin.format.container}, plugins=False)


def test_archivey_config_refuses_a_policy_of_the_wrong_type() -> None:
    with pytest.raises(ArchiveyUsageError, match="formats"):
        ArchiveyConfig(formats={C.ZIP})  # type: ignore[arg-type]


# --- allows(): the design.md §3 table ---------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "opens", "refuses"),
    [
        (
            {"only": {C.ZIP, C.TAR}},
            [ArchiveFormat.ZIP, ArchiveFormat.TAR],
            [
                ArchiveFormat.TAR_GZ,
                ArchiveFormat.GZ,
                ArchiveFormat.SEVEN_Z,
                ArchiveFormat.DIRECTORY,
            ],
        ),
        (
            {"only": {C.TAR, *StreamFormat}},
            [ArchiveFormat.TAR, ArchiveFormat.TAR_GZ, ArchiveFormat.TAR_ZST],
            [ArchiveFormat.GZ, ArchiveFormat.ZIP],
        ),
        (
            {"only": {C.RAW_STREAM, S.GZIP}},
            [ArchiveFormat.GZ],
            [ArchiveFormat.TAR_GZ, ArchiveFormat.XZ],
        ),
        (
            {"exclude": {S.BROTLI}},
            [ArchiveFormat.ZIP, ArchiveFormat.GZ, ArchiveFormat.TAR],
            [ArchiveFormat.BROTLI, ArchiveFormat(C.TAR, S.BROTLI)],
        ),
        (
            {"exclude": {C.RAR}, "plugins": False},
            [ArchiveFormat.ZIP, ArchiveFormat.ISO],
            [ArchiveFormat.RAR],
        ),
    ],
)
def test_allows_takes_both_halves_of_the_format(
    kwargs: dict[str, object],
    opens: list[ArchiveFormat],
    refuses: list[ArchiveFormat],
) -> None:
    policy = FormatPolicy(**kwargs)  # type: ignore[arg-type]
    assert [f for f in opens if not policy.allows(f)] == []
    assert [f for f in refuses if policy.allows(f)] == []


def test_plugin_formats_follow_plugins_and_only(clean_registry: None) -> None:
    listed = _plugin_with("listed").format
    other = _plugin_with("other").format
    assert FormatPolicy().allows(listed)
    assert not FormatPolicy(plugins=False).allows(listed)
    only = FormatPolicy(only={C.ZIP, listed.container})
    assert only.allows(listed)
    assert only.allows(ArchiveFormat.ZIP)
    assert not only.allows(other)
    assert not only.allows(ArchiveFormat.TAR)
    assert not FormatPolicy(exclude={listed.container}).allows(listed)


# --- refusals at open ---------------------------------------------------------------


def test_a_compression_missing_from_only_is_refused_by_name(tmp_path: Path) -> None:
    path = tmp_path / "a.tar.gz"
    path.write_bytes(_tar_gz_bytes())
    config = _config(only={C.TAR})
    with pytest.raises(UnsupportedFeatureError) as exc_info:
        open_archive(path, config=config)
    assert exc_info.value.source_format == ArchiveFormat.TAR_GZ
    assert "StreamFormat.GZIP" in str(exc_info.value)
    assert "a.tar.gz" in str(exc_info.value)
    # Detection still reports the true built-in format.
    assert detect_format(path, config=config).format == ArchiveFormat.TAR_GZ
    with open_archive(path, config=_config(only={C.TAR, S.GZIP})) as reader:
        assert [m.name for m in reader.members()] == ["a.txt"]


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        (
            {"only": {C.ZIP}},
            "only= does not list ContainerFormat.TAR or StreamFormat.GZIP; add them",
        ),
        (
            {"exclude": {C.TAR}, "only": {S.GZIP}},
            "exclude= lists ContainerFormat.TAR.",
        ),
        (
            {"exclude": {C.TAR, S.GZIP}},
            "exclude= lists ContainerFormat.TAR, and exclude= lists StreamFormat.GZIP.",
        ),
        (
            {"exclude": {S.GZIP}, "only": {C.ZIP}},
            (
                "exclude= lists StreamFormat.GZIP, and only= does not list "
                "ContainerFormat.TAR; add it"
            ),
        ),
    ],
)
def test_one_refusal_names_every_entry_to_change(
    kwargs: dict[str, object], expected: str
) -> None:
    refusal = FormatPolicy(**kwargs)._refusal(ArchiveFormat.TAR_GZ)  # type: ignore[arg-type]
    assert refusal is not None
    assert expected in refusal


def test_format_does_not_bypass_the_policy(tmp_path: Path) -> None:
    path = tmp_path / "a.zip"
    path.write_bytes(_zip_bytes())
    with pytest.raises(UnsupportedFeatureError, match="exclude= lists"):
        open_archive(path, format=ArchiveFormat.ZIP, config=_config(exclude={C.ZIP}))


def test_a_directory_is_refused_when_only_omits_it(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"a")
    with pytest.raises(UnsupportedFeatureError, match="ContainerFormat.DIRECTORY"):
        open_archive(tmp_path, config=_config(only={C.ZIP}))


def test_the_policy_refusal_comes_before_the_pipe_refusal() -> None:
    class Pipe(io.RawIOBase):
        def __init__(self, data: bytes) -> None:
            self._buf = io.BytesIO(data)

        def readable(self) -> bool:
            return True

        def readinto(self, b: bytearray) -> int:  # type: ignore[override]
            return self._buf.readinto(b)

    # 7z cannot be read from a pipe; the caller who turned it off is told that instead.
    seven_z = b"7z\xbc\xaf\x27\x1c" + bytes(26)
    with pytest.raises(UnsupportedFeatureError, match="ContainerFormat.SEVEN_Z"):
        open_archive(
            io.BufferedReader(Pipe(seven_z)), config=_config(exclude={C.SEVEN_Z})
        )


def test_open_stream_follows_the_policy(tmp_path: Path) -> None:
    path = tmp_path / "a.gz"
    path.write_bytes(gzip.compress(b"alpha"))
    with pytest.raises(UnsupportedFeatureError, match="StreamFormat.GZIP") as exc_info:
        open_stream(path, config=_config(exclude={S.GZIP}))
    assert exc_info.value.archive_name == str(path)
    with pytest.raises(UnsupportedFeatureError, match="ContainerFormat.RAW_STREAM"):
        open_stream(path, format=S.GZIP, config=_config(only={C.TAR, S.GZIP}))
    tar_gz = tmp_path / "a.tar.gz"
    tar_gz.write_bytes(_tar_gz_bytes())
    with open_stream(tar_gz, config=_config(only={C.TAR, S.GZIP})) as stream:
        assert stream.read(5) == b"a.txt"


# --- plugins the policy turns off ------------------------------------------------


def test_an_off_plugin_runs_no_probe_even_when_every_probe_is_asked_for(
    clean_registry: None,
) -> None:
    calls: list[bytes] = []

    def probe(prefix: bytes) -> bool:
        calls.append(prefix)
        return prefix.startswith(_MAGIC)

    plugin = _plugin_with("probed", probe=probe)
    data = build_toya(_ENTRIES)
    config = ArchiveyConfig(
        always_probe_content=True, formats=FormatPolicy(plugins=False)
    )
    with pytest.raises(FormatDetectionError) as exc_info:
        detect_format(io.BytesIO(data), config=config)
    assert not calls
    assert "ArchiveyConfig.formats" in str(exc_info.value)
    assert plugin.format.display_name in str(exc_info.value)
    # The same call with the plugin on runs it and finds the format.
    on = ArchiveyConfig(always_probe_content=True)
    assert detect_format(io.BytesIO(data), config=on).format == plugin.format
    assert calls


def test_an_off_plugin_does_not_shadow_an_allowed_one(clean_registry: None) -> None:
    # Both claim the same magic; the first registered would win if it were a candidate.
    first = _plugin_with("first", magic=(Magic(0, _MAGIC),))
    second = _plugin_with("second", magic=(Magic(0, _MAGIC),))
    data = build_toya(_ENTRIES)
    assert detect_format(io.BytesIO(data)).format == first.format
    config = _config(exclude={first.format.container})
    info = detect_format(io.BytesIO(data), config=config)
    assert info.format == second.format
    skipped = {(s.tier, s.reason) for s in info.unavailable_tiers}
    assert ("near_magic", TierSkipReason.NOT_ENABLED_BY_POLICY) in skipped
    with open_archive(io.BytesIO(data), config=config) as reader:
        assert reader.format == second.format


def test_an_off_plugins_extension_is_not_a_guess(
    clean_registry: None, tmp_path: Path
) -> None:
    plugin = _plugin_with("named")
    path = tmp_path / "a.named"
    path.write_bytes(b"no magic here" * 4)
    assert detect_format(path).format == plugin.format
    config = _config(plugins=False)
    with pytest.raises(FormatDetectionError, match="ArchiveyConfig.formats"):
        detect_format(path, config=config)
    with pytest.raises(FormatDetectionError, match="ArchiveyConfig.formats"):
        open_archive(path, config=config)


def test_an_unrelated_off_plugin_keeps_the_advice_for_magic_less_streams(
    clean_registry: None,
) -> None:
    # The plugin could never claim these bytes; the message adds the policy to the
    # advice that reaches the formats the file might be, and claims no probe ran.
    plugin = _plugin_with("named", magic=(Magic(0, _MAGIC),))
    data = b"hello world, nothing archive-like here\n" * 20
    with pytest.raises(FormatDetectionError) as exc_info:
        detect_format(io.BytesIO(data), config=_config(plugins=False))
    message = str(exc_info.value)
    assert "(.lzma, .zz, .br)" in message
    assert "content probe" not in message
    assert f"turns off the plugin formats {plugin.format.display_name}" in message


def test_internal_detections_carry_the_policy() -> None:
    # The stub check and the empty-listing rescan detect under probe_config; a caller
    # whose only setting is the policy must not get the default policy back there.
    config = _config(plugins=False)
    assert probe_config(config).formats == config.formats
    assert probe_config(ArchiveyConfig()) is DEFAULT_ARCHIVEY_CONFIG


def test_format_naming_an_off_plugin_is_refused_by_name(
    clean_registry: None, tmp_path: Path
) -> None:
    plugin = _plugin_with("named", magic=(Magic(0, _MAGIC),))
    path = tmp_path / "a.named"
    path.write_bytes(build_toya(_ENTRIES))
    with pytest.raises(UnsupportedFeatureError, match="plugins=False"):
        open_archive(path, format=plugin.format, config=_config(plugins=False))


def test_a_builtin_answer_does_not_depend_on_the_policy(clean_registry: None) -> None:
    _plugin_with("ziplike", magic=(Magic(0, b"PK\x03\x04"),))
    data = _zip_bytes()
    for kwargs in ({}, {"plugins": False}, {"only": {C.TAR}}):
        info = detect_format(io.BytesIO(data), config=_config(**kwargs))
        assert info.format == ArchiveFormat.ZIP


# --- replacement plugins ------------------------------------------------------------


class _StdlibZipReader(IndexedReader[str]):
    """Reads a ZIP with the standard library: a stand-in for a plugin that supports
    something the built-in reader refuses."""

    def __init__(self, source: PluginSource, context: PluginContext) -> None:
        self._zip = zipfile.ZipFile(source.view(0))

    def iter_members(self) -> Iterator[MemberRecord[str]]:
        for info in self._zip.infolist():
            member = ArchiveMember(
                type=MemberType.FILE,
                name=info.filename,
                raw_name=info.filename.encode(),
                size=info.file_size,
            )
            yield MemberRecord(member, locator=info.filename)

    def open_member(self, member: ArchiveMember, locator: str) -> MemberData:
        return MemberData(self._zip.open(locator))

    def close(self) -> None:
        self._zip.close()


_opened: list[str] = []


class StdlibZipPlugin(FormatPlugin):
    format = ArchiveFormat.ZIP

    def open(self, source: PluginSource, context: PluginContext) -> _StdlibZipReader:
        _opened.append(type(self).__name__)
        return _StdlibZipReader(source, context)


_REPLACE_ZIP = ArchiveyConfig(formats=FormatPolicy(replace={C.ZIP: StdlibZipPlugin}))


@pytest.fixture(autouse=True)
def _reset_opened() -> None:
    _opened.clear()


def test_a_replacement_reads_the_builtin_container(tmp_path: Path) -> None:
    path = tmp_path / "a.zip"
    path.write_bytes(_zip_bytes())
    with open_archive(path, config=_REPLACE_ZIP) as reader:
        assert reader.format == ArchiveFormat.ZIP
        assert reader.format_info is not None
        assert not reader.format_info.from_plugin
        assert [m.name for m in reader.members()] == ["a.txt"]
        with reader.open("a.txt") as stream:
            assert stream.read() == b"alpha"
    assert _opened == ["StdlibZipPlugin"]
    # Detection is the built-in's, with or without the replacement.
    plain = detect_format(path)
    replaced = detect_format(path, config=_REPLACE_ZIP)
    assert (replaced.format, replaced.detected_by) == (plain.format, plain.detected_by)
    # Without it, the built-in reader opens the file.
    with open_archive(path) as reader:
        assert [m.name for m in reader.members()] == ["a.txt"]
    assert _opened == ["StdlibZipPlugin"]


def test_a_replacement_is_hashable_and_compares_by_value() -> None:
    again = FormatPolicy(replace={C.ZIP: StdlibZipPlugin})
    assert again == _REPLACE_ZIP.formats
    assert hash(again) == hash(_REPLACE_ZIP.formats)
    assert hash(_REPLACE_ZIP)
    assert dict(again.replace) == {C.ZIP: StdlibZipPlugin}


def _replacement(**attrs: object) -> type[FormatPlugin]:
    return type("Variant", (StdlibZipPlugin,), attrs)


class _SequentialZip(SequentialFormatPlugin):
    format = ArchiveFormat.ZIP

    def open_sequential(self, context: PluginContext) -> SequentialReader:
        raise NotImplementedError


@pytest.mark.parametrize(
    ("replace", "match"),
    [
        ({C.TAR: StdlibZipPlugin}, "cannot replace ContainerFormat.TAR"),
        ({C.DIRECTORY: StdlibZipPlugin}, "cannot replace ContainerFormat.DIRECTORY"),
        ({"zip": StdlibZipPlugin}, "ContainerFormat keys"),
        ({C.ZIP: object}, "FormatPlugin subclass"),
        ({C.ZIP: _SequentialZip}, "SequentialFormatPlugin"),
        ({C.SEVEN_Z: StdlibZipPlugin}, "must be ArchiveFormat"),
        ({C.ZIP: _replacement(magic=(Magic(0, b"PK"),))}, "declares extensions"),
        ({C.ZIP: _replacement(extensions=(".zap",))}, "declares extensions"),
        ({C.ZIP: _replacement(probe=lambda prefix: True)}, "declares extensions"),
        ([C.ZIP], "mapping"),
    ],
)
def test_replacement_refusals(replace: object, match: str) -> None:
    with pytest.raises(ArchiveyUsageError, match=match):
        FormatPolicy(replace=replace)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs", [{"exclude": {C.ZIP}}, {"only": {C.TAR}}], ids=["exclude", "only"]
)
def test_a_replaced_container_must_be_allowed(kwargs: dict[str, object]) -> None:
    with pytest.raises(ArchiveyUsageError, match="turns it off"):
        FormatPolicy(replace={C.ZIP: StdlibZipPlugin}, **kwargs)  # type: ignore[arg-type]


def test_a_replacement_is_not_given_a_volume_set(tmp_path: Path) -> None:
    data = _zip_bytes()
    (tmp_path / "a.zip.001").write_bytes(data[:40])
    (tmp_path / "a.zip.002").write_bytes(data[40:])
    with open_archive(tmp_path / "a.zip.001") as reader:
        assert [m.name for m in reader.members()] == ["a.txt"]
    with pytest.raises(UnsupportedFeatureError, match="multi-volume set"):
        open_archive(tmp_path / "a.zip.001", config=_REPLACE_ZIP)
    assert _opened == []


def test_a_replacement_is_not_given_an_archive_behind_a_stub(tmp_path: Path) -> None:
    path = tmp_path / "a.exe"
    path.write_bytes(_pe_stub() + _zip_bytes())
    assert detect_format(path).payload_offset > 0
    with pytest.raises(UnsupportedFeatureError, match="self-extracting stub"):
        open_archive(path, config=_REPLACE_ZIP)
    assert _opened == []


def test_a_replacement_is_not_given_a_pipe() -> None:
    class Pipe(io.RawIOBase):
        def __init__(self, data: bytes) -> None:
            self._buf = io.BytesIO(data)

        def readable(self) -> bool:
            return True

        def readinto(self, b: bytearray) -> int:  # type: ignore[override]
            return self._buf.readinto(b)

    with pytest.raises(StreamNotSeekableError):
        open_archive(
            io.BufferedReader(Pipe(_zip_bytes())), streaming=True, config=_REPLACE_ZIP
        )
    assert _opened == []


def test_a_replacements_missing_requirement_is_reported_before_it_opens(
    tmp_path: Path,
) -> None:
    plugin = _replacement(requires=("archivey_no_such_module",), install_hint="hint")
    path = tmp_path / "a.zip"
    path.write_bytes(_zip_bytes())
    config = ArchiveyConfig(formats=FormatPolicy(replace={C.ZIP: plugin}))
    with pytest.raises(PackageNotInstalledError, match="archivey_no_such_module"):
        open_archive(path, config=config)
    assert _opened == []
