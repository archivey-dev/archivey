"""The DMG reader against two other readers: dpp-py (Rust) and libyal (C).

7-Zip is the main oracle (``test_dmg.py``, ``test_dmg_apfs.py``); these two add a second
and third opinion on the same images, the ``hdiutil`` fixtures and the builder images.
Each runs in a subprocess (``tests/dmg_oracle_dump.py``). Every file and symlink that
both readers list must match, and every entry the other reader lists must be one
archivey lists too, except the gaps below, which are the other reader's (checked by hand
against the macOS listing in ``fixtures/external/dmg_hdiutil/`` and the builder's own
tree):

- Both list the HFS+ private folders that a mount hides, and list a FIFO as an empty
  file.
- dpp reads every path of an HFS+ file hard link as an empty file (its README: hard
  links are not supported), refuses ADC runs, reads decmpfs type 12 as an error, gives
  APFS plain-key (case-sensitive) volumes no entries, and reads the builder's sparse
  APFS file wrongly.
- libyal has no xz runs, fails on some bzip2 runs (``invalid run length`` / ``invalid
  origin pointer``) and on symlinks in the bzip2 HFS+ fixture, and refuses the builder's
  sparse APFS file and decmpfs type 12.
"""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import unicodedata
from pathlib import Path

import pytest

from archivey import MemberType, open_archive
from tests import apfs_build as a, dmg_build as d
from tests.conftest import requires

_FIXTURES = Path(__file__).parent / "fixtures" / "external" / "dmg_hdiutil"
_DUMP = Path(__file__).parent / "dmg_oracle_dump.py"

_ORACLES = {
    "dpp": requires("dpp"),
    "libyal": requires("pymodi", "pyfshfs", "pyfsapfs"),
}

# Entries a mount hides and archivey hides too; both other readers list them.
_HIDDEN = (
    "\x00\x00\x00\x00HFS+ Private Data",
    "␀␀␀␀HFS+ Private Data",
    ".HFS+ Private Directory Data\r",
)

# Whole images the other reader cannot read: (reader, image id) -> its error, matched.
_REFUSED = {
    ("dpp", "hfs-UDCO.dmg"): "ADC",
    **{
        ("dpp", f"hfs-builder-{layout}-adc"): "ADC" for layout in ("gpt", "apm", "none")
    },
    ("libyal", "hfs-ULMO.dmg"): "LZMA",
    ("libyal", "apfs-ULMO.dmg"): "LZMA",
    ("libyal", "apfs-UDBZ.dmg"): "bzip",
    **{
        ("libyal", f"hfs-builder-{layout}-{codec}"): err
        for layout in ("gpt", "apm", "none")
        for codec, err in (("xz", "LZMA"), ("bzip2", "bzip"))
    },
}

# Members the other reader gets wrong or cannot read: (reader, image id prefix) ->
# names.
_HFS_BUILDER_LINKS = {"sub dir/first.txt", "other/second.txt"}
_WRONG = {
    ("dpp", "hfs-U"): {"hello.txt", "sub dir/hardlink.txt"},
    ("dpp", "hfs-builder"): _HFS_BUILDER_LINKS | {"comp/t12.txt", "comp/big12.bin"},
    ("dpp", "apfs-builder"): {"sparse.bin", "comp/t12.txt"},
    ("libyal", "hfs-UDBZ.dmg"): {"*"},
    ("libyal", "apfs-builder"): {"sparse.bin", "comp/t12.txt"},
}


def _hfs_builder(layout: str, codec: int) -> bytes:
    from tests.test_dmg import _image

    return _image(layout=layout, codec=codec)


def _apfs_builder(layout: str) -> bytes:
    from tests.test_dmg_apfs import _container

    return a.apfs_dmg(_container(hashed=True).container, layout=layout)


_CODECS = {
    "raw": d.RAW,
    "zlib": d.ZLIB,
    "bzip2": d.BZIP2,
    "xz": d.LZMA,
    "adc": d.ADC,
    "lzfse": d.LZFSE,
}
_IMAGES: dict[str, object] = {
    **{
        name: name
        for name in (
            "hfs-UDZO.dmg",
            "hfs-UDBZ.dmg",
            "hfs-ULFO.dmg",
            "hfs-ULMO.dmg",
            "hfs-UDRO.dmg",
            "hfs-UDCO.dmg",
            "apfs-UDZO.dmg",
            "apfs-UDBZ.dmg",
            "apfs-ULFO.dmg",
            "apfs-ULMO.dmg",
            "apfs-UDRO.dmg",
        )
    },
    **{
        f"hfs-builder-{layout}-{codec}": (layout, codec)
        for layout in ("gpt", "apm", "none")
        for codec in _CODECS
    },
    **{f"apfs-builder-{layout}": layout for layout in ("gpt", "apm", "none")},
}


def _image_bytes(image_id: str) -> bytes:
    spec = _IMAGES[image_id]
    if image_id.startswith("hfs-builder"):
        layout, codec = spec  # type: ignore[misc]
        return _hfs_builder(layout, _CODECS[codec])
    if image_id.startswith("apfs-builder"):
        return _apfs_builder(spec)  # type: ignore[arg-type]
    return (_FIXTURES / image_id).read_bytes()


def _ours(image: bytes) -> dict[str, list[str]]:
    """archivey's entries in the dump's shape; a hard link has its target's data."""
    entries: dict[str, list[str]] = {}
    links: dict[str, str] = {}
    with open_archive(io.BytesIO(image)) as reader:
        for member in reader.members():
            name = unicodedata.normalize("NFC", member.name.rstrip("/"))
            if member.type is MemberType.FILE:
                entries[name] = [
                    "file",
                    hashlib.sha256(reader.read(member)).hexdigest(),
                ]
            elif member.type is MemberType.DIRECTORY:
                entries[name] = ["dir"]
            elif member.type is MemberType.SYMLINK:
                entries[name] = ["symlink", member.link_target or ""]
            elif member.type is MemberType.HARDLINK:
                links[name] = unicodedata.normalize("NFC", member.link_target or "")
            else:  # a FIFO, device or socket: both other readers list it as a file
                entries[name] = ["other"]
    for name, target in links.items():
        entries[name] = entries[target]
    return entries


def _theirs(tmp_path: Path, reader: str, image: bytes) -> dict:
    path = tmp_path / "image.dmg"
    path.write_bytes(image)
    done = subprocess.run(
        [sys.executable, str(_DUMP), reader, str(path)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    return json.loads(done.stdout)


def _hidden(name: str) -> bool:
    return name.startswith(_HIDDEN)


@pytest.mark.parametrize("image_id", sorted(_IMAGES))
@pytest.mark.parametrize(
    "reader", [pytest.param(r, marks=m) for r, m in _ORACLES.items()]
)
def test_other_readers_agree_with_archivey(
    tmp_path: Path, reader: str, image_id: str
) -> None:
    image = _image_bytes(image_id)
    theirs = _theirs(tmp_path, reader, image)
    refused = _REFUSED.get((reader, image_id))
    if refused is not None:
        # Pinned so that a reader that learns the codec makes this test start comparing.
        assert not theirs["ok"], f"{reader} now reads {image_id}: drop it from _REFUSED"
        assert refused in theirs["error"]
        pytest.skip(f"{reader} cannot read {image_id}: {theirs['error'][:120]}")
    assert theirs["ok"], theirs["error"]
    wrong: set[str] = set()
    for (who, prefix), names in _WRONG.items():
        if who == reader and image_id.startswith(prefix):
            wrong |= names
    if "*" in wrong:
        pytest.skip(f"{reader} cannot read the members of {image_id}")
    ours = _ours(image)
    got = {n: v for n, v in theirs["entries"].items() if not _hidden(n)}
    if reader == "dpp" and image_id.startswith("apfs-builder") and not got:
        pytest.fail("dpp lists nothing in a hashed-key APFS volume")
    for name, entry in ours.items():
        if name in wrong or entry == ["other"]:
            continue
        assert got.get(name) == entry, (name, entry, got.get(name))
    assert set(got) <= set(ours), sorted(set(got) - set(ours))
