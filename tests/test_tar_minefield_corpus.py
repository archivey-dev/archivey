"""Compare Archivey's TAR reader with GNU tar on the tar-minefield corpus.

Off by default. Point ``ARCHIVEY_TAR_MINEFIELD`` at a clone of
https://github.com/haampie/tar-minefield (its home page is stoppels.ch/tar)::

    git clone https://github.com/haampie/tar-minefield /path/to/tar-minefield
    ARCHIVEY_TAR_MINEFIELD=/path/to/tar-minefield \\
      uv run --no-sync pytest tests/test_tar_minefield_corpus.py -q -n 0

Run it in one process (``-n 0``): N12 writes the fixed path ``/tmp/tar-minefield-absolute``
when an extractor follows its absolute name, and every case checks that path, so
parallel workers would see each other's N12 run.

Each case in ``suite/archives`` is a crafted ``.tar`` with a verdict (``accept``,
``tolerate`` or ``reject``) and, unless it is to be rejected, the tree an extractor
should write. Archivey extracts it three ways (``POLICIES``): ``TRUSTED`` with
``overwrite=REPLACE`` as ``tar -x`` does, the defaults (``STRICT``), and the safest
settings, the defaults with ``DiagnosticPolicy.STRICT``, held to tar-codec's bar. Each goes into ``root/x/y/dest``,
so that a write outside the destination is caught. The run is classified as the
corpus's ``suite/check.py`` classifies one (the logic is re-implemented here: the test
runs no code from the clone): ``expected`` (the expected tree), ``rejected`` (a member
refused or the open failed), ``other`` (another tree) or ``outside``. GNU tar 1.35's
and tar-codec's results are the corpus's own, ``contrib/matrix/matrix.json``.

The pins in ``tests/fixtures/tar_minefield/expected.json`` hold, per case and policy,
Archivey's outcome, a digest of its tree, whether that tree is GNU tar's, and the
diagnostic codes a listing reports. ``scripts/gen_tar_minefield_expected.py`` rewrites
them from a clone, and writes ``dev-docs/tar-minefield-results.md`` from the pins and
the reasons below.

Two tests need no clone and run in the normal suite: every case where Archivey fails
the corpus's verdict or extracts another tree than GNU tar must have a reason in
``TRIAGE`` (``DEFAULTS_TRIAGE`` for the defaults), no reason may outlive its difference,
and the results page must be what the pins and the reasons render.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from archivey import ArchiveyConfig, DiagnosticPolicy, open_archive
from archivey.exceptions import ArchiveyError
from archivey.types import ExtractionPolicy, OverwritePolicy

_ENV = "ARCHIVEY_TAR_MINEFIELD"
REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_PATH = Path(__file__).parent / "fixtures" / "tar_minefield" / "expected.json"
RESULTS_PATH = REPO_ROOT / "dev-docs" / "tar-minefield-results.md"
# The runs: (extraction policy, overwrite policy, diagnostic policy). "trusted" is the
# one closest to tar -x; "strict_diag" is the safest settings, the defaults with
# DiagnosticPolicy.STRICT, which refuses every shape in ARCHIVE_INTEGRITY_CODES.
POLICIES: dict[str, tuple[ExtractionPolicy, OverwritePolicy, DiagnosticPolicy]] = {
    "trusted": (ExtractionPolicy.TRUSTED, OverwritePolicy.REPLACE, DiagnosticPolicy()),
    "defaults": (ExtractionPolicy.STRICT, OverwritePolicy.ERROR, DiagnosticPolicy()),
    "strict_diag": (
        ExtractionPolicy.STRICT,
        OverwritePolicy.ERROR,
        DiagnosticPolicy.STRICT,
    ),
}
TITLES = {
    "trusted": "TRUSTED",
    "defaults": "Defaults (STRICT)",
    "strict_diag": "Safest (STRICT + DiagnosticPolicy.STRICT)",
}
# The corpus's column for Astral's tar-codec (as in uv), the safety yardstick for
# strict_diag.
TAR_CODEC = "Rust tar-codec, as in uv"
# N12's absolute name, in /tmp, which an extractor that follows it can write without
# root (suite/check.py's ABSOLUTE).
ABSOLUTE = Path("/tmp/tar-minefield-absolute")

# Why Archivey, under TRUSTED, fails the corpus's verdict or writes another tree than
# GNU tar. TRUSTED is the policy closest to tar -x; the defaults' own differences follow.
# The rule that decides most of them is DR-6: read a format as its official tool does,
# here GNU tar, so a "reject" case GNU tar extracts is extracted the same way, and a
# shape no real writer produces is reported with MEMBER_HEADER_AMBIGUOUS (in
# ARCHIVE_INTEGRITY_CODES, so DiagnosticPolicy.STRICT refuses it) instead of refused.
_AS_GNU = "Extracted as GNU tar extracts it (DR-6)"
_AMBIGUOUS = (
    f"{_AS_GNU}, and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer "
    "produces the shape and another reader can frame or name it differently"
)
_DUPLICATES = (
    f"{_AS_GNU}: OverwritePolicy.REPLACE, as tar -x, lets the later member win, and "
    "the shape is in real tarballs. overwrite=ERROR, the default, refuses the second "
    "member instead"
)
TRIAGE: dict[str, str] = {
    "F03-end-lone-zero-block": (
        f"{_AS_GNU}, reported with ARCHIVE_EOF_MARKER_MISSING: real tarballs end "
        "this way, and the members before the block are whole"
    ),
    "F06-checksum-signed": (
        f"{_AMBIGUOUS} (signed_checksum): GNU tar accepts a header that matches "
        "either the unsigned or the signed sum; SunOS 4 and Ultrix tars wrote the "
        "signed one, no current writer does"
    ),
    "F07-end-archive-after": (
        f"{_AS_GNU}, reported with ARCHIVE_TRAILING_DATA: what follows the end "
        "marker is not read, as GNU tar does not read it"
    ),
    "F09-end-zero-block-then-member": (
        f"{_AS_GNU}, reported with ARCHIVE_EOF_MARKER_MISSING and "
        "ARCHIVE_TRAILING_DATA: the zero block ends the archive, as in GNU tar "
        "without --ignore-zeros"
    ),
    "F10-extended-pax-size-before-gnu-long": f"{_AMBIGUOUS} (mixed_chain)",
    "F11-magic-odd-version": (
        f"{_AMBIGUOUS} (magic_version): GNU tar reads any POSIX magic as ustar, "
        "whatever the version"
    ),
    "F12-number-size-gap": (
        f"{_AMBIGUOUS} (field_tail): the size ends at the blank, as in GNU tar"
    ),
    "F13-pax-newline-in-path": (
        f"{_AMBIGUOUS} (newline_in_value): a record is framed by its length, as "
        "POSIX says, so the newline is a byte of the path. Newlines in xattr and ACL "
        "values are real and not reported"
    ),
    "F15-pax-size-on-dir": (
        "Not the corpus's GNU tar column, which reads the header after the "
        "directory as dir/smuggled: that is upstream GNU tar 1.35, before the fix "
        "for CVE-2026-5704 (a member injected past a directory's data). The patched "
        "GNU tar 1.35 (Ubuntu 1.35+dfsg-3ubuntu0.4, measured 2026-10-30) skips the "
        "blocks the PAX size declares and writes the directory alone, and so does "
        "Archivey, reporting MEMBER_DIRECTORY_DATA_IGNORED. Listing and extraction "
        "agree on one member either way"
    ),
    "F16-type-unknown": (
        f"{_AS_GNU}: an unknown typeflag with data is a file, as GNU tar extracts "
        "it, reported with MEMBER_TYPE_UNKNOWN (maintainer ruling 2026-10-17)"
    ),
    "F19-pax-global-between-extended-and-member": f"{_AMBIGUOUS} (global_in_chain)",
    "F20-pax-global-size": f"{_AMBIGUOUS} (global_member_field)",
    "F26-pax-size-leading-zero": (
        f"{_AMBIGUOUS} (leading_zero): the size is decimal, as POSIX and GNU tar "
        "read it"
    ),
    "F28-pax-newline-in-comment": (
        f"{_AMBIGUOUS} (newline_in_value): the newline cannot start a size record, "
        "as for F13"
    ),
    "F33-size-on-dir": (
        f"{_AMBIGUOUS} (size_on_no_data): the next header is read, as GNU tar "
        "reads it (maintainer ruling 2026-10-30 to report it)"
    ),
    "F34-size-on-hardlink": f"{_AMBIGUOUS} (size_on_no_data)",
    "F35-pax-size-on-hardlink": (
        "Not the corpus's GNU tar column, which reads the header after the link "
        "as smuggled: Archivey skips the blocks the PAX size declares, as the "
        "CVE-2026-5704-patched GNU tar 1.35 does (F15), and reports "
        "MEMBER_LINK_DATA_IGNORED"
    ),
    "K01-kind-trailing-slash-file": (
        f"{_AS_GNU}: a regular file named a/ is a directory, as GNU tar's "
        "extract.c makes it. Not reported: v7 tarballs (sendmail, tcp_wrappers) "
        "store directories this way"
    ),
    "K02-linkname-on-file": (
        f"{_AS_GNU}: a regular file's link name is not used. Not reported: bgen "
        "1.1.7 writes one, and only a reader that goes by the link name reads a link"
    ),
    "K03-symlink-trailing-slash": (
        f"{_AS_GNU}: the trailing slash is dropped, reported with "
        "MEMBER_NAME_NORMALIZED"
    ),
    "N07-symlink-absolute": (
        "Refused under every policy: an absolute symlink target leads outside the "
        "destination, which no ExtractionPolicy writes (GNU tar writes the link as "
        "stored). The corpus tolerates a refusal"
    ),
    "N08-extended-pax-path-and-gnu-long-name": (
        f"{_AMBIGUOUS} (both_families): the PAX path wins, as in GNU tar"
    ),
    "N09-extended-two-pax-headers": (
        f"{_AMBIGUOUS} (repeated): the last x header wins, as in GNU tar"
    ),
    "N10-format-star": (
        f"{_AS_GNU}: under the POSIX magic the whole prefix field is the name "
        "prefix. Not reported: star writes this format (berkeley-db, ncurses)"
    ),
    "N11-gnu-prefix-field": (
        f"{_AS_GNU}: under the GNU magic those bytes are not a prefix. Not "
        "reported: GNU tar writes times there in incremental archives"
    ),
    "N12-name-absolute": (
        "TRUSTED re-roots an absolute name inside the destination, as GNU tar "
        "strips the leading slash. Nothing is written outside it"
    ),
    "N13-name-backslash": (
        "TRUSTED keeps a backslash as a character, as GNU tar on POSIX does. Not "
        "reported: texi2html and gstreamer-docs tarballs have them"
    ),
    "N14-name-bytes-after-nul": (
        f"{_AMBIGUOUS} (field_tail): the name ends at the NUL, as in GNU tar"
    ),
    "N18-name-not-utf8": (
        "TRUSTED writes the name's bytes, as GNU tar does. Not reported: aspell "
        "tarballs have Latin-1 names"
    ),
    "N19-pax-nul-in-path": (
        f"{_AMBIGUOUS} (nul_in_value): the value ends at the NUL, as in GNU tar"
    ),
    "N20-pax-repeated-key": (
        f"{_AMBIGUOUS} (repeated): the last record wins in an x header, as in GNU tar"
    ),
    "N21-pax-global-path": f"{_AMBIGUOUS} (global_member_field)",
    "N22-pax-path-empty": (
        f"{_AMBIGUOUS} (empty_value): the empty path is skipped and the header's "
        "name stays, as in GNU tar"
    ),
    "N23-extended-gnu-long-then-pax": f"{_AMBIGUOUS} (mixed_chain)",
    "N24-pax-hdrcharset-binary": (
        "TRUSTED writes the name's bytes, as GNU tar does. Not reported: "
        "hdrcharset=BINARY is POSIX's way to store them, and readers disagree only "
        "on whether to write or skip the file, not on its name"
    ),
    "N26-pax-global-path-then-empty": (
        f"{_AMBIGUOUS} (global_member_field, global_replaced): each g header "
        "replaces the global records before it, as in GNU tar"
    ),
    "S04-hardlink-to-itself": (
        f"{_AS_GNU}: the file stays as it is; 27 real tarballs have the shape"
    ),
    "S06-hardlink-to-symlink": (
        f"{_AS_GNU}: the hard link is a second link to the symlink, not to its target"
    ),
    "S07-tree-duplicate-file-differs": _DUPLICATES,
    "S08-tree-duplicate-file-dir": _DUPLICATES,
    "S09-tree-duplicate-file-identical": _DUPLICATES,
    "S10-tree-symlink-then-file": (
        f"{_DUPLICATES}. The file replaces the link, never writing through it"
    ),
}

# Why Archivey, under the defaults (STRICT), writes another tree than GNU tar where TRUSTED does not
# say why already. STRICT writes a name in a spelling every OS can hold (ADR 0013), so
# a name GNU tar writes as stored can land under another name, or be refused.
_STRICT_NAMES = "STRICT rewrites the name to a spelling every OS can hold (ADR 0013)"
_STRICT_REFUSES = (
    "STRICT refuses a name that another OS or reader takes differently (ADR 0013, "
    "2026-10-31 amendment)"
)
DEFAULTS_TRIAGE: dict[str, str] = {
    "S08-tree-duplicate-file-dir": (
        "overwrite=ERROR, the default, refuses the second member where GNU tar lets "
        "the later member win, so the defaults pass this reject case"
    ),
    "F13-pax-newline-in-path": f"{_STRICT_REFUSES}: it holds a newline",
    "N10-format-star": f"{_STRICT_NAMES}: the trailing blank is dropped",
    "N12-name-absolute": "STRICT refuses an absolute name (ADR 0013)",
    "N13-name-backslash": f"{_STRICT_REFUSES}: Windows reads the backslash as a separator",
    "N15-name-control-character": f"{_STRICT_REFUSES}: it holds a newline",
    "N18-name-not-utf8": f"{_STRICT_REFUSES}: the byte 0xE9 is not UTF-8",
    "N24-pax-hdrcharset-binary": f"{_STRICT_REFUSES}: the byte 0xE9 is not UTF-8",
}

# Why Archivey, with the safest settings, fails a case's verdict. This is the safety
# bar, so the reason must justify reading the shape rather than refusing it.
DIAG_TRIAGE: dict[str, str] = {
    "F16-type-unknown": (
        "MEMBER_TYPE_UNKNOWN is deliberately out of DiagnosticPolicy.STRICT: real "
        "writers emit vendor typeflags with data (Solaris tar's X extended headers and "
        "A ACLs), GNU tar extracts them as files, and Archivey delivers the data as a "
        "FILE, so nothing is hidden"
    ),
    "K01-kind-trailing-slash-file": (
        "v7 tarballs (sendmail 8.18.2, tcp_wrappers 7.6) store directories this way, "
        "and GNU tar makes it a directory; refusing it refuses real archives"
    ),
    "K02-linkname-on-file": (
        "bgen 1.1.7 writes it, and the link name of a regular file is never used: "
        "only a reader that ignores the typeflag makes a link"
    ),
    "N10-format-star": (
        "star writes this format (berkeley-db 18.1.40, ncurses 5.9); under the POSIX "
        "magic the whole field is the prefix, as GNU tar reads it"
    ),
    "N11-gnu-prefix-field": (
        "GNU tar's incremental archives put times in those bytes; under the GNU magic "
        "they are never a prefix"
    ),
    "S04-hardlink-to-itself": (
        "27 real tarballs have it (cuDNN binaries in Spack, xscreensaver 6.12); the "
        "file stays as it is"
    ),
    "S06-hardlink-to-symlink": (
        "octa 8.4 has it; the hard link is a second symlink to the same target, "
        "checked like the first, never followed"
    ),
    "S07-tree-duplicate-file-differs": (
        "fish 4.7.1 has it: a later file supersedes an earlier file of the same name, "
        "as with tar -x, under every OverwritePolicy. A later member that changes the "
        "kind at that name (S08, a directory after a file) is not a supersede and goes "
        "through overwrite=ERROR, which refuses it"
    ),
    "S09-tree-duplicate-file-identical": (
        "cabal sdist tarballs have it; the later copy supersedes the earlier one, as "
        "for S07"
    ),
    "S10-tree-symlink-then-file": (
        "The file supersedes the link, as for S07, and is never written through it: "
        "the link is replaced, so the write stays in the destination"
    ),
}


def _root() -> Path | None:
    value = os.environ.get(_ENV)
    return Path(value) if value else None


def _entry(path: Path, dest: Path) -> dict[str, Any]:
    """One path as the corpus's trees give it; a link into dest starts with DEST."""
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        target = os.readlink(path)
        if target == str(dest) or target.startswith(str(dest) + os.sep):
            target = "DEST" + target[len(str(dest)) :]
        return {"kind": "symlink", "target": target}
    if stat.S_ISDIR(st.st_mode):
        return {"kind": "directory"}
    if stat.S_ISREG(st.st_mode):
        data = path.read_bytes()
        return {
            "kind": "file",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "executable": bool(st.st_mode & stat.S_IXUSR),
        }
    return {"kind": "other"}


def _walk(top: Path, dest: Path) -> dict[str, dict[str, Any]]:
    tree = {}
    for dirpath, dirnames, filenames in os.walk(top):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            tree[path.relative_to(top).as_posix()] = _entry(path, dest)
    return tree  # os.walk does not descend into a symlinked directory


def _same(tree: dict[str, Any], expected: dict[str, Any]) -> bool:
    """Whether a tree is the expected one, comparing what that says of each entry."""
    return set(tree) == set(expected) and all(
        tree[path].get(key) == value
        for path, entry in expected.items()
        for key, value in entry.items()
    )


def classify(case: dict[str, Any], rejected: bool, tree: dict[str, Any]) -> str:
    """``expected``, ``rejected`` or ``other``, as suite/check.py's classify()."""
    if rejected:
        return "rejected"
    if case["verdict"] != "reject" and _same(tree, expected_tree(case)):
        return "expected"
    return "other"


def passes(case: dict[str, Any], outcome: str) -> bool:
    """Whether an outcome passes the case, as suite/check.py's problems() judges."""
    if outcome == "expected":
        return True
    return outcome == "rejected" and case["verdict"] != "accept"


def expected_tree(case: dict[str, Any]) -> dict[str, Any]:
    return {
        e["path"]: {k: v for k, v in e.items() if k != "path"}
        for e in case.get("tree", ())
    }


def tree_digest(tree: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(tree, sort_keys=True).encode()).hexdigest()[:16]


def extract_with_archivey(
    archive: Path,
    policy: ExtractionPolicy,
    overwrite: OverwritePolicy = OverwritePolicy.REPLACE,
    diagnostics: DiagnosticPolicy | None = None,
) -> tuple[bool, dict[str, Any], dict[str, Any]]:
    """(rejected, tree, outside) of one extraction into a fresh root/x/y/dest.

    Rejected means the open raised an ``ArchiveyError``, or a member was not written:
    any status but extracted, overwritten or superseded, so a link whose target is
    unavailable counts too, as GNU tar exits non-zero for it. Any other exception is
    a bug and fails the run.
    """
    if os.path.lexists(ABSOLUTE):
        raise RuntimeError(
            f"{ABSOLUTE} exists before the run and would count as written: remove it"
        )
    root = Path(tempfile.mkdtemp(prefix="tar-minefield-"))
    dest = root / "x" / "y" / "dest"
    dest.mkdir(parents=True)
    cwd = Path.cwd()
    os.chdir(root)  # A write relative to the cwd lands in root, outside dest.
    try:
        try:
            config = ArchiveyConfig(diagnostic_policy=diagnostics or DiagnosticPolicy())
            with open_archive(archive, config=config) as reader:
                report = reader.extract_all(dest, policy=policy, overwrite=overwrite)
            rejected = any(
                result.status.value not in ("extracted", "overwritten", "superseded")
                for result in report.results
            )
        except ArchiveyError:
            rejected = True
    finally:
        os.chdir(cwd)
    tree = _walk(dest, dest)
    outside = {
        path: entry
        for path, entry in _walk(root, dest).items()
        if path not in ("x", "x/y", "x/y/dest") and not path.startswith("x/y/dest/")
    }
    if os.path.lexists(ABSOLUTE):
        outside[str(ABSOLUTE)] = _entry(ABSOLUTE, dest)
        if ABSOLUTE.is_dir() and not ABSOLUTE.is_symlink():
            shutil.rmtree(ABSOLUTE)
        else:
            ABSOLUTE.unlink()
    shutil.rmtree(root)
    return rejected, tree, outside


def listing_codes(archive: Path) -> list[str]:
    """The diagnostic codes a listing reports, or the error class of a refusal."""
    try:
        with open_archive(archive) as reader:
            reader.members()
            return sorted(str(code) for code in reader.diagnostics.counts)
    except ArchiveyError as exc:
        return [f"error: {type(exc).__name__}"]


def tool_result(
    case: dict[str, Any], matrix: dict[str, Any], tool: str = "GNU tar"
) -> dict[str, Any]:
    """A tool's outcome and tree digest, from the corpus's matrix."""
    run = matrix["cases"][case["name"]][tool]
    rejected = run.get("error") is not None
    tree = run.get("tree") or {}
    return {
        "outcome": classify(case, rejected, tree),
        "tree": tree_digest(tree),
    }


PASSES_WITH = {
    "accept": ["expected"],
    "tolerate": ["expected", "rejected"],
    "reject": ["rejected"],
}


def corpus_fields(case: dict[str, Any], matrix: dict[str, Any]) -> dict[str, Any]:
    """The pinned fields that come from the corpus, not from Archivey."""
    return {
        "id": case["id"],
        "verdict": case["verdict"],
        "passes_with": PASSES_WITH[case["verdict"]],
        "gnu": tool_result(case, matrix),
        "tar_codec": tool_result(case, matrix, TAR_CODEC),
    }


def clone_commit(root: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def load_matrix(root: Path) -> dict[str, Any]:
    return json.loads(
        (root / "contrib" / "matrix" / "matrix.json").read_text(encoding="utf-8")
    )


def run_case(
    case: dict[str, Any], archive: Path, gnu: dict[str, Any]
) -> dict[str, Any]:
    """The pinned form of Archivey's runs over one case."""
    result: dict[str, Any] = {"codes": listing_codes(archive)}
    for label, (policy, overwrite, diagnostics) in POLICIES.items():
        rejected, tree, outside = extract_with_archivey(
            archive, policy, overwrite, diagnostics
        )
        assert not outside, f"{case['name']} under {label} wrote outside: {outside}"
        outcome = classify(case, rejected, tree)
        result[label] = {
            "outcome": outcome,
            "tree": tree_digest(tree),
            "gnu_tree": outcome != "rejected"
            and gnu["outcome"] != "rejected"
            and tree_digest(tree) == gnu["tree"],
        }
    return result


def load_cases(root: Path) -> dict[str, dict[str, Any]]:
    cases = {}
    for path in sorted((root / "suite" / "archives").glob("*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        case["name"] = path.stem
        cases[path.stem] = case
    return cases


def load_expected() -> dict[str, Any]:
    return json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))


def agrees_with_gnu(pin: dict[str, Any], label: str) -> bool:
    """Whether Archivey's run under ``label`` is GNU tar's result: its tree, or a
    refusal where GNU tar refuses."""
    run = pin[label]
    return run["gnu_tree"] or run["outcome"] == pin["gnu"]["outcome"] == "rejected"


def _reader_agrees_with_gnu(pin: dict[str, Any], key: str) -> bool:
    """Whether another reader's pinned result (``tar_codec``) is GNU tar's."""
    run, gnu = pin[key], pin["gnu"]
    if run["outcome"] == "rejected" or gnu["outcome"] == "rejected":
        return run["outcome"] == gnu["outcome"]
    return run["tree"] == gnu["tree"]


def differs(pin: dict[str, Any], label: str) -> bool:
    """Whether Archivey's run under ``label`` fails the verdict or is not GNU tar's."""
    return (
        not agrees_with_gnu(pin, label)
        or pin[label]["outcome"] not in pin["passes_with"]
    )


# The corpus's categories (its METHOD.md), by the first letter of a case's id, and
# the library mechanism a case of each should map to under the safest settings
# (maintainer request 2026-10-31).
CATEGORIES = {
    "F": (
        "Framing",
        (
            "Where a member's data ends and which headers belong to it. A shape no real "
            "writer produces should be a diagnostic in ARCHIVE_INTEGRITY_CODES, which "
            "DiagnosticPolicy.STRICT refuses, unless well justified."
        ),
    ),
    "N": (
        "Names",
        (
            "Which field names a member, and how a path is normalized. A name another OS "
            "or reader takes differently should be blocked by ExtractionPolicy.STRICT."
        ),
    ),
    "K": (
        "Kinds",
        "Whether a member is a file, directory or link. Mixed: decided case by case.",
    ),
    "S": (
        "Order and state",
        "Duplicate paths and links between members. Mixed: decided case by case.",
    ),
}


def needs_reason(pin: dict[str, Any], label: str) -> bool:
    """Whether a run owes a reason. TRUSTED owes one where it fails the verdict or is
    not GNU tar's result; the defaults only where they also differ from TRUSTED; the safest
    settings wherever they fail the verdict, which is the safety bar."""
    run_passes = pin[label]["outcome"] in pin["passes_with"]
    if label == "strict_diag":
        return not run_passes
    if label == "defaults":
        return differs(pin, label) and (
            not differs(pin, "trusted") or pin["defaults"] != pin["trusted"]
        )
    return differs(pin, label)


def _reasons() -> dict[str, dict[str, str]]:
    return {"trusted": TRIAGE, "defaults": DEFAULTS_TRIAGE, "strict_diag": DIAG_TRIAGE}


def case_link(name: str) -> str:
    """The case's page on the corpus's site, which explains it in full."""
    case_id = name.split("-", 1)[0]
    return f"[{case_id}](https://stoppels.ch/tar/{case_id}.html)"


def _mark(passed: bool) -> str:
    return "✅" if passed else "❌"


def render_results(expected: dict[str, Any]) -> str:
    """dev-docs/tar-minefield-results.md, from the pins and the reasons."""
    cases = expected["cases"]
    total = len(cases)

    def passed(pin: dict[str, Any], label: str) -> bool:
        return pin[label]["outcome"] in pin["passes_with"]

    lines = [
        "# tar-minefield results",
        "",
        "<!-- Written by scripts/gen_tar_minefield_expected.py; edit the reasons in",
        "tests/test_tar_minefield_corpus.py and rerun it. -->",
        "",
        (
            "Archivey's TAR reader against the [tar-minefield](https://stoppels.ch/tar/) "
            "corpus ([source](https://github.com/haampie/tar-minefield) at "
            f"`{expected['tar_minefield'][:8]}`), next to GNU tar 1.35 and Astral's "
            "tar-codec, as the corpus's own matrix gives them. "
            "`tests/test_tar_minefield_corpus.py` runs it; its docstring says how. "
            "Each case links to its page on the corpus's site."
        ),
        "",
        "Archivey runs each case three ways:",
        "",
        (
            "- **TRUSTED**: `ExtractionPolicy.TRUSTED`, `overwrite=REPLACE`, the "
            "closest to `tar -x`."
        ),
        (
            "- **Defaults**: what `extract_all()` does when given nothing: "
            "`ExtractionPolicy.STRICT`, `overwrite=ERROR` and the default "
            "`DiagnosticPolicy`, which reports the odd framing shapes but reads them. "
            "It fails more cases than Safest for that reason."
        ),
        (
            "- **Safest** (STRICT + DiagnosticPolicy.STRICT): the default "
            "`ExtractionPolicy.STRICT` and `overwrite=ERROR`, with "
            "`DiagnosticPolicy.STRICT`, which refuses every shape in "
            "`ARCHIVE_INTEGRITY_CODES`. It is held to tar-codec's bar: every case it "
            "fails has a reason below."
        ),
        "",
        (
            "An outcome is `expected` (the case's tree), `rejected` (the open failed or "
            "a member was not written, an unavailable link target included) or `other` "
            "(another tree). A `reject` case passes only when rejected, a `tolerate` "
            "case when rejected or expected, an `accept` case only when expected. In "
            "the tables ✅ passes and ❌ fails the case's verdict; ≠GNU marks a TRUSTED "
            "or Defaults run whose result is not GNU tar's (its tree, or a refusal where "
            "GNU tar refuses). No case writes outside the destination: the test fails "
            "if one does."
        ),
        "",
        (
            "Each case below gives a reason per run that owes one: Safest wherever it "
            "fails the verdict, TRUSTED wherever it fails it or is not GNU tar's "
            "result, and Defaults only where TRUSTED's reason does not cover it."
        ),
        "",
        "## Summary",
        "",
        "| Run | Passes | GNU tar's result |",
        "| --- | --- | --- |",
    ]
    for label in POLICIES:
        n_pass = sum(passed(pin, label) for pin in cases.values())
        same = sum(agrees_with_gnu(pin, label) for pin in cases.values())
        lines.append(f"| {TITLES[label]} | {n_pass} of {total} | {same} of {total} |")
    for title, key in (("GNU tar 1.35", "gnu"), ("tar-codec", "tar_codec")):
        n_pass = sum(
            pin[key]["outcome"] in pin["passes_with"] for pin in cases.values()
        )
        same_cell = (
            f"{sum(_reader_agrees_with_gnu(pin, key) for pin in cases.values())} "
            f"of {total}"
            if key != "gnu"
            else ""
        )
        lines.append(f"| {title} | {n_pass} of {total} | {same_cell} |")
    lines += [
        "",
        (
            "The safest settings and tar-codec refuse what GNU tar extracts, so a low "
            "count in the last column is expected for them: they are held to the "
            "corpus's verdicts, not to GNU tar's trees."
        ),
    ]
    explained = {
        name
        for name, pin in cases.items()
        if any(needs_reason(pin, label) for label in POLICIES)
    }
    safest = [name for name in cases if needs_reason(cases[name], "strict_diag")]
    others = [name for name in cases if name in explained and name not in safest]
    lines += [
        "",
        "## Why the safest settings still differ",
        "",
        (
            "The corpus is written for software distribution: a package manager, or a "
            "scanner that checks a tarball before another tool extracts it. There the "
            "danger is two readers making different trees of one archive, so a "
            '"reject" verdict marks any shape some reader takes differently, even '
            "one that real tarballs use. The corpus's own policy accepts 99.79% of the "
            "source tarballs it scanned and expects the rest to be allowed one by one, "
            "by checksum."
        ),
        "",
        (
            "Archivey's goal is to read every archive the format's own tool reads, so "
            "it holds the safest settings to the corpus's verdicts except where a "
            "shape is in real archives and Archivey's reading of it has a single "
            "answer that keeps every write inside the destination. Each case below "
            "names the writers that produce it. None of them is a difference we plan "
            "to fix: Archivey reads each one as GNU tar does, or refuses it, and no "
            "case writes outside the destination under any run."
        ),
        "",
        (
            "tar-codec, the corpus's strictest reader, fails 13 cases too, among them "
            "the duplicate members, the star and GNU prefix layouts and the link name "
            "on a file: the shapes real tarballs use. Its sources do not say why; the "
            "likely reason is the same trade, since uv must read the sdists already "
            "published. The cases where tar-codec refuses and Archivey reads are "
            "marked 🔴, the ones both read 🟡."
        ),
        "",
        (
            "A caller who checks an archive with Archivey and extracts it with "
            "another tool can still refuse every one of them: each reports a "
            "diagnostic outside `ARCHIVE_INTEGRITY_CODES` (MEMBER_TYPE_UNKNOWN, "
            "MEMBER_READERS_DISAGREE or MEMBER_NAME_DUPLICATE), which "
            "`DiagnosticPolicy.PEDANTIC` or `raise_on=` turns into a refusal. The "
            "codes column of the table shows which."
        ),
        "",
        "## Cases the safest settings fail",
        "",
        (
            "The safety bar: each case STRICT + DiagnosticPolicy.STRICT fails, 🔴 where "
            "tar-codec passes it and 🟡 where tar-codec fails it too, with why Archivey "
            "reads it rather than refusing it. The reasons for the other runs follow "
            "where they have their own."
        ),
        "",
    ]
    lines += _entries(cases, safest, codec_mark=True)
    lines += [
        "## Other cases TRUSTED or Defaults fails or reads unlike GNU tar",
        "",
        (
            "Cases the safest settings pass, but where TRUSTED or Defaults fails the "
            "verdict or does not give GNU tar's result. TRUSTED and Defaults only "
            "report the framing shapes DiagnosticPolicy.STRICT refuses, so they pass "
            "fewer cases."
        ),
        "",
    ]
    lines += _entries(cases, others, codec_mark=False)
    refusing = [
        name
        for name, pin in cases.items()
        if pin["gnu"]["outcome"] == "expected"
        and pin["strict_diag"]["outcome"] == "rejected"
    ]
    lenient = sum(pin["verdict"] != "accept" for pin in cases.values())
    lines += [
        "## Cases Safest refuses that GNU tar extracts",
        "",
        (
            f"A refusal passes a `reject` or `tolerate` case, {lenient} of {total}, so "
            "the pass counts bound how permissive a run is, not how strict. These are "
            "the cases where Safest refuses and GNU tar writes the expected tree: the "
            "cost of the safety bar. The code is what the listing reports."
        ),
        "",
    ]
    if not refusing:
        lines += ["None.", ""]
    for name in refusing:
        pin = cases[name]
        codes = ", ".join(f"`{c}`" for c in pin["codes"]) or "nothing reported"
        lines.append(
            f"- {case_link(name)} `{name}` ({pin['verdict']}; tar-codec "
            f"{pin['tar_codec']['outcome']}): {codes}"
        )
    lines.append("")
    lines += [
        "## Every case",
        "",
        (
            "Why links to the case's entry above, for a case where any run fails the "
            "verdict or a TRUSTED or Defaults run is not GNU tar's result."
        ),
        "",
        (
            "| Case | Verdict | GNU tar | tar-codec | TRUSTED | Defaults | Safest | "
            "Listing reports | Why |"
        ),
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    def cell(pin: dict[str, Any], label: str) -> str:
        run = pin[label]
        mark = "" if label == "strict_diag" or agrees_with_gnu(pin, label) else " ≠GNU"
        return f"{_mark(passed(pin, label))} {run['outcome']}{mark}"

    def tool(pin: dict[str, Any], key: str) -> str:
        outcome = pin[key]["outcome"]
        return f"{_mark(outcome in pin['passes_with'])} {outcome}"

    for name, pin in cases.items():
        codes = ", ".join(f"`{c}`" for c in pin["codes"]) or "nothing"
        lines.append(
            f"| {case_link(name)} `{name.split('-', 1)[1]}` | {pin['verdict']} | "
            f"{tool(pin, 'gnu')} | {tool(pin, 'tar_codec')} | {cell(pin, 'trusted')} | "
            f"{cell(pin, 'defaults')} | {cell(pin, 'strict_diag')} | {codes} | "
            f"{f'[why](#{_anchor(name)})' if name in explained else ''} |"
        )
    return "\n".join(lines) + "\n"


def _anchor(name: str) -> str:
    """The id GitHub gives the case's ``####`` heading: its name, lowercased."""
    return name.lower()


def _entries(
    cases: dict[str, dict[str, Any]], names: list[str], *, codec_mark: bool
) -> list[str]:
    """One ``####`` entry per case, grouped by category: its outcomes, then a reason
    for each run that owes one."""
    lines: list[str] = []
    for letter, (title, mechanism) in CATEGORIES.items():
        group = [name for name in names if name.startswith(letter)]
        if not group:
            continue
        lines += [f"### {title}", "", mechanism, ""]
        for name in group:
            pin = cases[name]
            outcomes = _outcomes(name, pin)
            if codec_mark:
                codec = pin["tar_codec"]["outcome"] in pin["passes_with"]
                outcomes = f"{'🔴' if codec else '🟡'} {outcomes}"
            lines += [f"#### {name}", "", outcomes, ""]
            for label in ("strict_diag", "trusted", "defaults"):
                if needs_reason(pin, label):
                    lines.append(f"- **{_SHORT[label]}**: {_reasons()[label][name]}")
            lines.append("")
    return lines


_SHORT = {
    "trusted": "TRUSTED",
    "defaults": "Defaults (STRICT)",
    "strict_diag": "Safest",
}


def _outcomes(name: str, pin: dict[str, Any]) -> str:
    """The case's verdict and every result, with its page on the corpus's site."""

    def result(title: str, outcome: str) -> str:
        return f"{title} {_mark(outcome in pin['passes_with'])} {outcome}"

    parts = [
        result("GNU tar", pin["gnu"]["outcome"]),
        result("tar-codec", pin["tar_codec"]["outcome"]),
        *(result(_SHORT[label], pin[label]["outcome"]) for label in POLICIES),
    ]
    return f"{case_link(name)}, {pin['verdict']}: " + ", ".join(parts) + "."


_ROOT = _root()
_EXPECTED = load_expected() if EXPECTED_PATH.exists() else {"cases": {}}


def _params() -> Iterator[Any]:
    if _ROOT is None:
        return
    for name in _EXPECTED["cases"]:
        yield pytest.param(name, id=name)


@pytest.mark.skipif(_ROOT is None, reason=f"set {_ENV} to a tar-minefield clone")
@pytest.mark.parametrize("name", list(_params()))
def test_archivey_matches_the_pinned_result(name: str) -> None:
    assert _ROOT is not None
    pin = _EXPECTED["cases"][name]
    case = load_cases(_ROOT)[name]
    archive = _ROOT / "suite" / "archives" / f"{name}.tar"
    fields = corpus_fields(case, load_matrix(_ROOT))
    assert fields == {key: pin[key] for key in fields}
    result = run_case(case, archive, fields["gnu"])
    assert result == {key: pin[key] for key in result}


@pytest.mark.skipif(_ROOT is None, reason=f"set {_ENV} to a tar-minefield clone")
def test_the_pins_cover_every_case() -> None:
    """The clone is the commit the pins were made from, with the same cases."""
    assert _ROOT is not None
    assert clone_commit(_ROOT) == _EXPECTED["tar_minefield"], (
        "the clone is not the pinned commit: rerun scripts/gen_tar_minefield_expected.py"
    )
    assert set(load_cases(_ROOT)) == set(_EXPECTED["cases"])


def test_every_case_has_a_category() -> None:
    """A case of a new category would drop out of the page's per-category lists."""
    assert {name[0] for name in _EXPECTED["cases"]} <= set(CATEGORIES)


def test_every_difference_has_a_reason() -> None:
    """Runs without a clone: the pins and the reasons must agree."""
    cases = _EXPECTED["cases"]
    for label, reasons in _reasons().items():
        missing = sorted(
            n for n, p in cases.items() if needs_reason(p, label) and n not in reasons
        )
        assert not missing, f"{label}: differences with no reason: {missing}"
        stale = sorted(
            n for n in reasons if n not in cases or not needs_reason(cases[n], label)
        )
        assert not stale, f"{label}: reasons with no difference: {stale}"


def test_the_results_page_is_current() -> None:
    assert RESULTS_PATH.read_text(encoding="utf-8") == render_results(_EXPECTED), (
        "rerun scripts/gen_tar_minefield_expected.py --results-only"
    )
