# Packaging and Extras

## Purpose

Install-time contract for Archivey: zero-dependency core, named optional extras,
supported runtimes, version exposure, and package layout. Runtime behavior when an
optional backend or system tool is absent belongs to `backend-registry` and the
format specs.

## Related specs

| Spec | Relationship |
| --- | --- |
| `backend-registry` | Runtime registration, graceful degradation, install hints |
| `format-7z` | Native 7z reading, optional codecs, AES, unsupported BCJ2 |
| `format-rar` | Native RAR metadata, `unrar` data path, crypto/checksum extras |
| `archive-reading` | Reader API exposed by core installs |
| `access-mode-and-cost` | Seekable gzip/bzip2 capability and access-cost reporting |
| `reader-concurrency` | Supported `MemberStreams.CONCURRENT` contract |
| `cli` | `[recommended]` extra supplies `tqdm`; command-line dependency |

## Requirements

### Requirement: Zero-dependency core

The system SHALL install with no third-party runtime dependencies when no extras are
requested. Bare `pip install archivey` MUST fully support every native or
stdlib-backed reader: ZIP, TAR including `tar.gz` / `tar.bz2` / `tar.xz` / `tar.Z`,
single-file GZ / BZ2 / XZ / Z (unix-compress), directories, and 7z reading for common
codecs (LZMA/LZMA2/BCJ/Delta/Deflate/BZip2/STORED) with CRC32 verification.

The system SHALL parse RAR metadata/listing natively in core with CRC32
verification. Reading RAR member data additionally requires an external RARLAB
`unrar` or `rar` system binary at runtime; no pip extra supplies that binary. RAR
members that carry only Blake2sp hashes are verified in core: BLAKE2sp is computed
natively on stdlib `hashlib` and needs no third-party package.

The build SHALL use `hatchling` and the distribution name `archivey`.

#### Scenario: core install matrix

| Case | Expected |
| --- | --- |
| `pip install archivey` with no extras | No third-party runtime packages installed |
| Core read of ZIP/TAR/GZ/BZ2/XZ/Z/directory/common-codec 7z | Fully functional |
| Core read of `.tar.Z` / bare `.Z` | Native LZW decode; no `uncompresspy` |
| Core RAR listing | Native metadata/listing works |
| Core RAR data read with no `unrar` or `rar` on `PATH` | Clear error says the external RARLAB `unrar` or `rar` tool is required |
| Core-only 7z write | Unavailable (writing not shipped); 7z reading still works |

### Requirement: Optional extras enable specific capabilities

The system SHALL expose exactly **four** user-facing extras, each answering a question a
user asks about their own environment rather than naming an internal dependency group.
7z and RAR reading are native for the common case, so extras cover less-common member
codecs, encryption, ISO, seeking accelerators, and the CLI.

| Extra | Pulls in | Enables |
| --- | --- | --- |
| *(none)* | stdlib only + native parsers | ZIP, TAR + stdlib compressed TAR variants including `.tar.Z`, GZ, BZ2, XZ, Z (unix-compress), directory, 7z read for common codecs (including every BCJ branch filter), RAR metadata/listing; RAR data still needs RARLAB `unrar` |
| `[recommended]` | `pyppmd`, `inflate64`, `brotli`, `lz4`, `backports.zstd` on Python <3.14, `cryptography`, `pycdlib`, `tqdm` | Every format and codec that installs everywhere: PPMd, Deflate64, Zstd, Brotli, LZ4, AES/crypto (7z, RAR headers, WinZip AES ZIP), ISO, CLI progress |
| `[seekable]` | `rapidgzip` | Faster gzip/bzip2 decompression and random access via rapidgzip / bundled `IndexedBzip2File` |
| `[free-threaded]` | `pycdlib`, `lz4`, `tqdm`, `backports.zstd` on Python <3.14, `cryptography` on Python >=3.14 | The subset that keeps the GIL **disabled** on free-threaded builds |
| `[all]` | `[recommended]` + `[seekable]` | Everything |

The system SHALL make `[recommended]` the sensible all-useful install and `[seekable]`
an opt-in on top of it. `[seekable]` MUST remain separate rather than folded into
`[recommended]`: it is a heavy native build that can fail to compile, importing it
into the process (which bzip2 random access does) re-enables the GIL on free-threaded
builds, and it carries the accelerator
close-before-finalize hazard recorded in `dev-docs/investigations/rapidgzip-upstream-report.md`.

The system SHALL NOT ship an extra per format. Removed names (`[7z]`, `[rar]`,
`[crypto]`, `[iso]`, `[zstd]`, `[lz4]`, `[cli]`, `[recommended-lite]`) MUST NOT be
reintroduced as aliases: format-named extras whose contents are capability-scoped are what
made install hints name the wrong thing.

Installing an extra MAY pull dependencies unrelated to the capability the caller wanted —
`[recommended]` is deliberately a single broad bundle. This supersedes the previous
requirement that each extra avoid unrelated dependencies, and is an accepted trade for a
table small enough that no user has to reason about it. (Extras, once published, can never
be removed; fewer names is the durable choice.)

`PackageNotInstalledError` install hints MUST name the extra that provides the missing
package (`[recommended]`, or `[seekable]` for rapidgzip) and MUST NOT name a format,
since member codecs are shared across containers.

A missing package is reported through two channels — the hint on `MissingComponent` (what
listing and `format_availability()` surface) and the message of the
`PackageNotInstalledError` raised when a read actually needs it. Both MUST derive from a
single declared requirement per package, so a packaging change cannot leave one channel
naming an extra that no longer exists while the other is correct.

AES block operations are the only third-party crypto dependency (`CryptoBackend` in
`internal/streams/crypto.py`; PBKDF2/SHA/HMAC are stdlib). The system SHALL ship exactly
one crypto backend, `cryptography`. Alternate AES providers MUST NOT be added merely to
work around a runtime where `cryptography` cannot yet install, since that doubles the
security surface for a transient gap; the backend abstraction is retained so the choice
stays cheap to revisit.

The system SHALL treat `[free-threaded]` as a **measured, moving** set: membership is
determined by whether importing the package leaves the GIL disabled on a free-threaded
build, it is expected to widen as the ecosystem adds support, and it MAY eventually
collapse into `[recommended]`. It MUST NOT be read as a claim that archivey is only
free-thread-safe with it. CI MUST install exactly this set on a free-threaded interpreter
and assert the GIL is still disabled, so the set cannot rot silently.

Optional packages that re-enable the GIL when imported (today `pyppmd`, `inflate64`,
`brotli` and `rapidgzip`) MUST NOT be imported by `import archivey` or by listing formats
and their availability. The system SHALL import each one only when it opens a stream that
decodes with it in this process, so having one installed does not by itself re-enable the
GIL. rapidgzip decodes only in a child process, so the caller's process never imports it. A
package that is installed but fails to import SHALL be treated as absent. So SHALL a package
archivey does not use on the running interpreter because it misreads data or crashes there
(today rapidgzip, lz4, pyppmd and inflate64 under PyPy): its `MissingComponent` carries a `reason`, and
every report of that component SHALL give the reason in place of the install advice, since
installing the package would not help. lz4, pyppmd and inflate64 lower format support, so
both reporting channels carry them. rapidgzip is an accelerator and never lowers support, so it
reaches only the `ON` refusal and the rewind report.

The system SHALL keep `[all]` as the conventional superset; it MUST resolve to
`[recommended]` + `[seekable]`.

Missing optional libraries MUST degrade by one rule: raise `PackageNotInstalledError` or
`UnsupportedFeatureError` only when bytes cannot be produced, and skip any integrity check
that cannot be computed with an integrity diagnostic/warning instead of failing the read.

RAR5 BLAKE2sp verification is implemented **natively on stdlib `hashlib`**
(`internal/hashing/blake2sp.py`) and requires no third-party package; no extra pulls a
Blake2sp backend.

The system SHALL keep `py7zr` and `rarfile` as **dev-only** test oracles. 7z writing is
not shipped in the current release (no 7z-writing extra); when writing lands in a later
phase it MAY reintroduce a dedicated write extra. BCJ2-filtered 7z members SHALL be
read on a core install, by archivey's own decoder; no extra adds or replaces it. No
user-facing extra SHALL pull an alternate RAR decompressor library or tool wrapper, and
no extra can supply the RARLAB `unrar` binary.

Development tools, oracle libraries, and fixture generators such as `ncompress` SHALL live
in the PEP 735 `dev` dependency group, not in user-facing runtime extras. The system SHALL
NOT list `uncompresspy` in any user-facing extra or the `dev` group.

#### Scenario: extras matrix

| Case | Expected |
| --- | --- |
| `pip install archivey` | No third-party runtime packages; core formats work |
| `pip install archivey[recommended]` | Every format/codec/crypto/ISO/CLI capability that installs everywhere; no rapidgzip |
| `pip install archivey[seekable]` after `[recommended]` | Adds gz/bz2 random access and speed |
| `pip install archivey[recommended]` on free-threaded 3.13 | **Fails** — `cryptography` -> `cffi` does not support free-threaded 3.13; documented, not worked around |
| `pip install archivey[free-threaded]` on free-threaded 3.13 | Resolves without `cryptography`; importing every included package leaves the GIL disabled |
| `pip install archivey[free-threaded]` on free-threaded 3.14 | Resolves **with** `cryptography` (cffi supports 3.14t); GIL still disabled |
| `[all]` on a free-threaded build, then `import archivey` and list formats | GIL still disabled; none of pyppmd, inflate64, brotli, rapidgzip imported |
| `pip install archivey[all]` | `[recommended]` + `[seekable]` |
| ZIP member needs Deflate64 with no extras | `PackageNotInstalledError` naming `archivey[recommended]`, never a format-named extra |
| Any optional package absent, compared across both channels | The hint in the raised error and the one reported by `format_availability()` are the same string |
| A package archivey does not use under PyPy that lowers format support (lz4, pyppmd, inflate64), installed, running under PyPy | Treated as absent; both channels give the reason archivey does not use it there, not install advice |
| `pip install archivey[7z]` | Fails: the extra no longer exists |

### Requirement: RAR data uses RARLAB unrar only

The system SHALL treat RARLAB `unrar` or RARLAB `rar` as the preferred external
decompressors for RAR member data. It MUST identify the binary on `PATH`
as a RARLAB build before use (`unrar` first, then `rar`) and MUST NOT implement a
fallback matrix to `unrar-free`, `unar`, `bsdtar`, `7z`, or other tools. The one
alternative is `unar`, used when `ArchiveyConfig.rar_decompressor` selects it, or
when it is `auto` (the default) and no RARLAB binary is found, provided it passes the
RAR5 check in `format-rar`. The choice is made once when the
archive opens; a read is never retried with the other program.
Member-data spawns SHALL use the `p` command only. A stored, encrypted member in one part
needs no program: archivey decrypts it with `cryptography` (`format-rar`).

#### Scenario: single-tool matrix

| Case | Expected |
| --- | --- |
| RARLAB `unrar` 6.0+ on `PATH` | Used for compressed member data and encrypted data archivey does not decrypt |
| RARLAB `rar` 6.0+ on `PATH`, `unrar` missing | Used for compressed member data and encrypted data archivey does not decrypt |
| RARLAB `unrar` 6.0+ and RARLAB `rar` both on `PATH` | `unrar` is used |
| RARLAB `unrar`/`rar` older than 6.0, or a RARLAB banner with no parseable version | `PackageNotInstalledError` naming the floor and the version found; refused at identification |
| Only `unrar-free` / `7z` on `PATH`, default config | `PackageNotInstalledError` naming RARLAB `unrar` or `rar`; they are never used |
| Only a `unar` 1.10+ that passes the RAR5 check on `PATH`, default config | `unar` is used for compressed member data |
| Only a `unar` that fails the RAR5 check on `PATH` (Debian and Ubuntu packages before 1.10.8+ds1-10), default config | `PackageNotInstalledError` naming RARLAB `unrar` or `rar`, as with neither present |
| Only `unar` on `PATH`, `rar_decompressor="unrar"` | `PackageNotInstalledError` naming RARLAB `unrar` or `rar` |
| `rar_decompressor="unar"`, a `unar` 1.10+ that passes the RAR5 check on `PATH` | `unar` is used for compressed member data; `unrar` is not |
| `rar_decompressor="auto"`, RARLAB `unrar` and `unar` on `PATH` | `unrar` is used |
| `rar_decompressor="auto"`, only a `unar` that passes the RAR5 check on `PATH` | `unar` is used |
| Listing without data reads | Succeeds without invoking any external decompressor |

### Requirement: Optional extras map only to libraries the code uses

User-facing extras SHALL list only libraries imported by `src/` at runtime for that
capability. A package used only by tests, decode oracles, fixture generation, or
fuzz harnesses MUST live in a PEP 735 dependency group (`dev`, `fuzz`, …) and be
absent from every user-facing extra.

The per-codec library choice and rationale SHALL be recorded in
`dev-docs/library-analysis.md`. A guard test or check script SHALL prevent dead or
test-only dependencies from returning to user-facing extras. A dependency pinned
ahead of its implementation phase, such as `tqdm` for the CLI, is permitted only
through an explicit documented allowlist in that guard.

#### Scenario: dependency-audit matrix

| Case | Expected |
| --- | --- |
| User-facing extra audited against `src/` imports | Every pinned package is reachable from runtime code or explicitly allowlisted |
| Library imported only by tests (`rarfile`, oracle `py7zr`, `ncompress`, fixture-only `pyzstd`) | Declared in `dev`; absent from runtime extras |
| `atheris` | Declared in `fuzz` group; absent from runtime extras and `[all]` |
| `pip install archivey[recommended]` on Python 3.11-3.13 | Installs `backports.zstd`; does not pull `zstandard` |
| `pip install archivey[recommended]` on Python 3.14+ | No third-party zstd package required; stdlib `compression.zstd` provides the backend |
| Extra lists a library no `src/` module imports and not allowlisted | Packaging audit fails |

### Requirement: CI-only fuzz dependency group

The system SHALL provide a PEP 735 dependency group named `fuzz` that installs
`atheris` (and any harness-only helpers it needs) for coverage-guided fuzz CI.
The `fuzz` group is **not** a user-facing runtime extra: it MUST NOT appear in
`[all]`, `[recommended]`, `[seekable]`, or `[free-threaded]`,
and MUST NOT be required to import or use `archivey` at runtime.

#### Scenario: fuzz packaging matrix

| Case | Expected |
| --- | --- |
| `pip install archivey` / `archivey[all]` | `atheris` not installed |
| Fuzz CI job | Installs via `uv sync --group fuzz` (plus target runtime needs) |
| Runtime import of `archivey` without fuzz group | No `atheris` dependency |

### Requirement: Supported runtime environment

The system SHALL declare and support Python 3.11 or newer on Linux, macOS, and
Windows. The public API remains synchronous.

Readers and writers are not generally thread-safe. The supported
`MemberStreams.CONCURRENT` contract — what concurrent opens, materialization,
passes, close/lifecycle, and same-stream rules mean — lives entirely in
`reader-concurrency` (default single-live-stream rule: `archive-reading`). This
capability SHALL NOT restate that contract.

When that contract is declared, behavior SHALL be data-race-free on regular
CPython and on the backend/runtime combinations exercised by the required Linux
CPython `3.13t` `free-threaded-concurrency` CI job. It MUST NOT depend on
incidental GIL serialization. Optional backends without a free-threaded-compatible
wheel are not claimed covered until an equivalent dedicated job executes them.
This is a packaging/CI correctness claim, not a parallel-speed guarantee. Writers
remain not thread-safe.

#### Scenario: runtime-support matrix

| Case | Expected |
| --- | --- |
| Install on Linux, macOS, or Windows under Python 3.11+ | Core and installed optional formats are supported |
| Install on Python older than 3.11 | `requires-python >=3.11` prevents installation |
| Required `3.13t` core-backend job runs concurrent reader tests | Same bytes/lifecycle behavior as regular CPython for covered backends |
| Optional backend unavailable in `3.13t` job | Ordinary-build coverage remains valid; free-threaded support is not claimed for that backend |
| Public docs for `MemberStreams.CONCURRENT` | Point at the supported contract without labeling it provisional |

### Requirement: Version metadata exposure

The system SHALL expose the installed version as `archivey.__version__`, resolved
from installed distribution metadata via `importlib.metadata` rather than a
hard-coded string. The lookup SHALL run on first access to the attribute (a
module-level `__getattr__`), not at `import archivey`, and its result SHALL be
cached.

#### Scenario: installed-version metadata

| Case | Expected |
| --- | --- |
| Caller reads `archivey.__version__` | Returns the version recorded in installed package metadata, e.g. `"0.2.0"` |
| `import archivey` without reading `__version__` | `__version__` is not yet bound in the module namespace |

### Requirement: Source package layout separates public API from implementation

The installable `archivey` package SHALL keep the supported public API at the
package root. Only public API modules appear in `archivey.__all__`: `core.py`,
`types.py`, `detection.py`, `config.py`, `diagnostics.py`, `exceptions.py`, `cost.py`,
and `reader.py`.
`archivey.__init__.py` SHALL re-export the public API so supported callers do not
import from `archivey.internal.*`. Every attribute of the package root SHALL be in
`archivey.__all__`, be a real submodule of `archivey` (`internal` included: importing
a submodule binds it on its parent package), or be private. A niche name stays in its public
submodule and is not also imported at the root: the diagnostic context payloads
(`NameNormalizationContext` and the others) come from `archivey.diagnostics`, and
`RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE` from `archivey.config`.

A public class SHALL be defined in a public module, so its own `__module__` is a
stable public path, `inspect.getsource` works on it, and data a caller persists does
not freeze the internal layout. `ArchiveStream` is the one exception: it is an
implementation class on the internal stream base and is never pickled.

Every class and function in `archivey.__all__` that is still defined under
`archivey.internal.*` SHALL report `archivey` as its `__module__`, so `pickle`,
`repr()` and `inspect.getmodule` name the public path. `typing.get_type_hints` SHALL
still resolve on every such class. `inspect.getsource` on such a class raises
`OSError`: it locates a class through its module and cannot follow the pin, and it
SHALL NOT return lines from another file.

Implementation code SHALL live under `archivey.internal.*` without public
stability guarantees. Format backends SHALL live under
`archivey.internal.backends.*` and register with the registry at import time.
Importing top-level `archivey` SHALL still register all bundled backends. The
codec/stream layer SHALL remain under `archivey.internal.streams.*`. Phase 4
extraction modules SHALL follow the same implementation-under-`internal` rule while
the public extraction types live on the public surface.

#### Scenario: package-layout matrix

| Case | Expected |
| --- | --- |
| Application uses documented API (`open_archive`, `ArchiveMember`, etc.) | `import archivey` or public re-exports suffice; no `archivey.internal` import required |
| Caller imports `archivey.internal.backends.zip` or old `archivey.formats.zip_reader` | Not documented, not in `__all__`, and not a stability promise |
| Caller imports `NameNormalizationContext` or `RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE` | From `archivey.diagnostics` or `archivey.config`; `from archivey import` raises `ImportError` |
| `archivey.OverwritePolicy.__module__`, `archivey.FormatInfo.__module__` | `archivey.types`, `archivey.detection`: the defining public module |
| `pickle.dumps(archivey.OverwritePolicy.SKIP)` | Records `archivey.types`, not `archivey.internal.…`; loads back to the same member |
| `inspect.getsource(archivey.OverwritePolicy)` | Returns the class source |
| A class in `__all__` other than `ArchiveStream` defined under `archivey.internal` | Test failure |
| `archivey.ArchiveStream.__module__` | `archivey` (pinned); `inspect.getsource` raises `OSError` on every supported Python |
| `typing.get_type_hints` on any class in `__all__` | Resolves |
| `import archivey` in a core-only environment | `list_supported_formats()` returns bundled formats without a prior `open_archive()` call |

### Requirement: archivey console entry points ship with the base package

The system SHALL install an `archivey` console script and support
`python -m archivey` from a base (no-extra) install. The `[recommended]` extra SHALL
continue to pull `tqdm` for progress output only; its absence MUST NOT
remove the command entry points.

#### Scenario: entry points vs progress extra

| Case | Expected |
| --- | --- |
| `pip install archivey` then `archivey --version` / `python -m archivey --version` | Command runs; version prints |
| `tqdm` not installed | Command runs; progress bars suppressed |
| `pip install archivey[recommended]` | Progress available when the CLI would show a bar |

### Requirement: an archivey-cli companion distribution installs the CLI with [recommended]

The repository SHALL ship a second distribution, `archivey-cli`, from
`packages/archivey-cli/`. It SHALL contain no Python modules. Its only runtime
dependency SHALL be `archivey[recommended]` pinned with `==` to its own version, which
SHALL equal the root `archivey` version. It SHALL install two console scripts, `archivey`
and `archivey-cli`, both pointing at the same entry point as the root `archivey` script.
The publish workflow SHALL build and upload it from the same tag as `archivey`.

Reason: Python packaging has no default extras, so `uvx archivey` runs the core install.
`uvx` runs the command named after the package, hence the `archivey-cli` script.

#### Scenario: companion package

| Case | Expected |
| --- | --- |
| `uvx archivey-cli --version -v` | Runs the archivey CLI; formats that need `[recommended]` report full support |
| `pipx install archivey-cli` then `archivey --version` | Command runs |
| Root version bumped without the companion's version or pin | `tests/test_cli_companion_package.py` fails |
| Tag `vX.Y.Z` where either built wheel has another version | `publish.yml` build job fails before upload |

### Requirement: Source distributions hold only what a build needs

The `archivey` sdist SHALL hold `src/`, `LICENSE`, `README.md`, `CHANGELOG.md`, and the
files the build backend adds (`pyproject.toml`, `PKG-INFO`, the repository's
`.gitignore`). The `archivey-cli` sdist SHALL hold its `LICENSE`, `README.md` and
`pyproject.toml` plus the same generated files. Tests SHALL NOT be shipped in the sdist.

Reason: without a list the build packs every tracked file (the 0.2.0rc1 sdist was about
7.5 MB with design notes and tests). Many tests read files that exist only in a git
checkout (`scripts/`, `review/`, `openspec/`, `.github/`), so the suite would not pass
from an unpacked sdist; packagers who run tests use the git tag.

#### Scenario: sdist contents

| Case | Expected |
| --- | --- |
| Tag `vX.Y.Z`, either sdist holds a top-level entry not listed above | `publish.yml` build job fails before upload |
| `only-include` in `pyproject.toml` changed without the `publish.yml` expectation | `tests/test_sdist_contents.py` fails |
| Unpack the `archivey` sdist and build a wheel from it | Builds; no `tests/` directory |

### Requirement: Terminal-safe display helpers live in the public archivey.terminal module

The package SHALL provide a public module, `archivey.terminal`, holding
`escape_control_chars`, `display_path` and `quoted`: the helpers for showing
archive-derived text to a person without letting it control the terminal. Names in its
`__all__` SHALL carry the same compatibility promise as `archivey.__all__`. The module
SHALL NOT be re-exported from `archivey`, so it does not crowd the root namespace or the
generated API reference for the package root. It SHALL import no other archivey module,
since `archivey.exceptions` imports it.

The enum-argument coercion the library's entry points apply
(`archivey.internal.enum_args`) is not part of this module and not public: a caller
passes the string spelling to the entry point, which converts it.

#### Scenario: terminal surface

| Case | Expected |
| --- | --- |
| `from archivey.terminal import escape_control_chars, display_path, quoted` | Works |
| `hasattr(archivey, "escape_control_chars")` / `"terminal" in archivey.__all__` | `False` / `False` |
| `escape_control_chars("ev\x1b[2Kil")` | `ev\x1b[2Kil` with the escape as four literal characters |

### Requirement: Destination naming rules live in the public archivey.paths module

The package SHALL provide a public module, `archivey.paths`, holding `numbered_name`:
the `name (N)` spelling `OverwritePolicy.RENAME` gives a renamed destination. A front
end that moves or renames what extraction wrote uses it to choose the name a direct
extraction would have chosen, and extraction itself SHALL use the same function, so the
two cannot drift. Names in its `__all__` SHALL carry the same compatibility promise as
`archivey.__all__`. The module SHALL NOT be re-exported from `archivey`.

#### Scenario: paths surface

| Case | Expected |
| --- | --- |
| `from archivey.paths import numbered_name` | Works |
| `"paths" in archivey.__all__` / `hasattr(archivey, "numbered_name")` | `False` / `False` |
| `numbered_name("photo.jpg", 1, is_dir=False)` | `"photo (1).jpg"` |
| `numbered_name("photos.2024", 2, is_dir=True)` | `"photos.2024 (2)"` |
| Two members named `photo.jpg` under `OverwritePolicy.RENAME` | The second is written as `numbered_name("photo.jpg", 1, is_dir=False)` |

### Requirement: archivey.paths.match_glob selects members by glob pattern

`archivey.paths` SHALL also provide `match_glob(*patterns: str, with_contents: bool =
False)`, returning a predicate
for `members=` (and for any caller filtering names). `members=`, `get()` and `open()`
keep matching stored names exactly; `match_glob` is the opt-in for patterns. A member
is selected when any pattern matches its whole name, case-sensitively:

- `*` matches any run of characters other than `/`; `?` one character other than `/`;
  `[...]` / `[!...]` one character from, or not from, the set, never `/`. An unclosed
  `[` is a literal. `\` is a literal character on every platform.
- `**` as a whole component matches zero or more components, so `a/**` also matches
  `a`; `**` inside a component is `*`.
- A directory is matched by its name without the trailing `/`. A pattern ending in `/`
  matches only directories (`ArchiveMember.is_dir`, or a `str` ending in `/`).
- No pattern, a pattern with an empty component (`""`, `/`, `a//b`; a leading `/` is
  allowed and matches an absolute member name), or a malformed `[...]` set raises
  `ArchiveyUsageError` (also a `ValueError`). A pattern that matches nothing records no
  diagnostic.
- With `with_contents=True`, a member is also selected when a folder it is in (any
  `/`-ended prefix of its name, without the `/`) matches as a directory. The CLI's
  member patterns are `match_glob(pattern, with_contents=True)`.

`archivey.paths` SHALL also provide `match_tar_glob(*patterns: str)`, the `tar` rules
side by side with `match_glob`: each pattern is matched with `fnmatch.fnmatchcase`
against the whole name (so `*` also matches `/`), as written and as `base/` and
`base/*` where `base` is the pattern without trailing `/`, so a folder's name selects
the folder and everything under it. No pattern, or a pattern with an empty component
(the same rule as `match_glob`), raises `ArchiveyUsageError`.

#### Scenario: match_glob patterns

| Pattern | Selects | Does not select |
| --- | --- | --- |
| `*.md` | `README.md` | `docs/index.md` |
| `**/*.md` | `README.md`, `docs/api/guide.md` | `notes.txt` |
| `docs/**` | `docs/`, `docs/index.md`, `docs/api/guide.md` | `docsx/a.md` |
| `docs/*` | `docs/index.md`, `docs/api/` | `docs/api/guide.md` |
| `*/` | `docs/` | `README.md`, `docs/api/` |
| `docs`, `with_contents=True` | `docs/`, `docs/api/guide.md` | `docs.txt` |
| `match_tar_glob("*.md")` | `README.md`, `docs/api/guide.md` | `notes.txt` |
| `match_tar_glob("docs")` | `docs/`, `docs/api/guide.md` | `docs.txt` |
| `a[*]b` | `a*b` | `axb` |
| `match_glob()` / `match_glob("")` / `match_glob("[z-a]")` | Raises `ArchiveyUsageError` | |
| `match_glob("a//b")` / `match_glob("//a")` | Raises `ArchiveyUsageError` | |
| `/etc/**` | `/etc/`, `/etc/passwd` | `etc/passwd` |
| `a[!-a]b` | `a0b` | `a-b`, `a/b` |
| `.` member (`is_dir`) with `*/` | Selected | |
