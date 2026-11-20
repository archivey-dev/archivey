## MODIFIED Requirements

### Requirement: Optional extras enable specific capabilities

The system SHALL expose exactly **four** user-facing extras, each answering a question a
user asks about their own environment rather than naming an internal dependency group.
7z and RAR reading are native for the common case, so extras cover less-common member
codecs, encryption, seeking accelerators, and the CLI.

| Extra | Pulls in | Enables |
| --- | --- | --- |
| *(none)* | stdlib only + native parsers | ZIP, TAR + stdlib compressed TAR variants including `.tar.Z`, GZ, BZ2, XZ, Z (unix-compress), directory, ISO (ISO 9660, Joliet, Rock Ridge, UDF), 7z read for common codecs (including every BCJ branch filter), RAR metadata/listing; RAR data still needs RARLAB `unrar` |
| `[recommended]` | `pyppmd`, `inflate64`, `brotli`, `lz4`, `backports.zstd` on Python <3.14, `cryptography`, `tqdm` | Every format and codec that installs everywhere: PPMd, Deflate64, Zstd, Brotli, LZ4, AES/crypto (7z, RAR headers, WinZip AES ZIP), CLI progress |
| `[seekable]` | `rapidgzip` | Faster gzip/bzip2 decompression and random access via rapidgzip / bundled `IndexedBzip2File` |
| `[free-threaded]` | `lz4`, `tqdm`, `backports.zstd` on Python <3.14, `cryptography` on Python >=3.14 | The subset that keeps the GIL **disabled** on free-threaded builds |
| `[all]` | `[recommended]` + `[seekable]` | Everything above |
| `[bzip3]` | `bzip3` | `.bz3` files and `.tar.bz3`; in neither `[recommended]` nor `[all]` |

The system SHALL make `[recommended]` the sensible all-useful install and `[seekable]`
an opt-in on top of it. `[seekable]` MUST remain separate rather than folded into
`[recommended]`: it is a heavy native build that can fail to compile, importing it into
the process (which bzip2 random access does) re-enables the GIL on free-threaded builds,
and it carries the accelerator close-before-finalize hazard recorded in
`dev-docs/investigations/rapidgzip-upstream-report.md`.

The system SHALL NOT ship an extra per format, with one exception: `[bzip3]`. The
`bzip3` package publishes wheels only for CPython 3.11 to 3.14 on Linux and Windows and
no source distribution, so it cannot join `[recommended]` ("installs everywhere") or
`[all]`, and its only use is the one format; its install hint names `archivey[bzip3]`.
Removed names (`[7z]`, `[rar]`, `[crypto]`, `[iso]`, `[zstd]`, `[lz4]`, `[cli]`,
`[recommended-lite]`) MUST NOT be reintroduced as aliases: format-named extras whose
contents are capability-scoped are what made install hints name the wrong thing.

`pycdlib` SHALL NOT be a runtime dependency of any extra, and `OptionalLibrary` SHALL
NOT name it: ISO is read by archivey's own parser. `pycdlib` stays in the `dev` group,
where tests use it to write images and as the reference parser.

Installing an extra MAY pull dependencies unrelated to the capability the caller wanted
— `[recommended]` is deliberately a single broad bundle. This supersedes the previous
requirement that each extra avoid unrelated dependencies, and is an accepted trade for a
table small enough that no user has to reason about it. (Extras, once published, can
never be removed; fewer names is the durable choice.)

`PackageNotInstalledError` install hints MUST name the extra that provides the missing
package (`[recommended]`, `[seekable]` for rapidgzip, or `[bzip3]` for bzip3) and MUST
NOT name another format, since member codecs are shared across containers.

A missing package is reported through two channels — the hint on `MissingComponent`
(what listing and `format_availability()` surface) and the message of the
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
free-thread-safe with it. CI MUST install exactly this set on a free-threaded
interpreter and assert the GIL is still disabled, so the set cannot rot silently.

Optional packages that re-enable the GIL when imported (today `pyppmd`, `inflate64`,
`brotli` and `rapidgzip`) MUST NOT be imported by `import archivey` or by listing
formats and their availability. The system SHALL import each one only when it opens a
stream that decodes with it in this process, so having one installed does not by itself
re-enable the GIL. rapidgzip decodes only in a child process, so the caller's process
never imports it. A package that is installed but fails to import SHALL be treated as
absent. So SHALL a package archivey does not use on the running interpreter because it
misreads data or crashes there (today rapidgzip, lz4, pyppmd and inflate64 under PyPy):
its `MissingComponent` carries a `reason`, and every report of that component SHALL give
the reason in place of the install advice, since installing the package would not help.
lz4, pyppmd and inflate64 lower format support, so both reporting channels carry them.
rapidgzip is an accelerator and never lowers support, so it reaches only the `ON`
refusal and the rewind report.

The system SHALL keep `[all]` as the conventional superset; it MUST resolve to
`[recommended]` + `[seekable]`.

Missing optional libraries MUST degrade by one rule: raise `PackageNotInstalledError` or
`UnsupportedFeatureError` only when bytes cannot be produced, and skip any integrity
check that cannot be computed with an integrity diagnostic/warning instead of failing
the read.

RAR5 BLAKE2sp verification is implemented **natively on stdlib `hashlib`**
(`internal/hashing/blake2sp.py`) and requires no third-party package; no extra pulls a
Blake2sp backend.

The system SHALL keep `py7zr` and `rarfile` as **dev-only** test oracles. 7z writing is
not shipped in the current release (no 7z-writing extra); when writing lands in a later
phase it MAY reintroduce a dedicated write extra. BCJ2-filtered 7z members SHALL be
read on a core install, by archivey's own decoder; no extra adds or replaces it. No
user-facing extra SHALL pull an alternate RAR decompressor library or tool wrapper, and
no extra can supply the RARLAB `unrar` binary.

Development tools, oracle libraries, and fixture generators such as `ncompress` SHALL
live in the PEP 735 `dev` dependency group, not in user-facing runtime extras. The
system SHALL NOT list `uncompresspy` in any user-facing extra or the `dev` group.

#### Scenario: extras matrix

| Case | Expected |
| --- | --- |
| `pip install archivey` | No third-party runtime packages; core formats work |
| `pip install archivey[recommended]` | Every format/codec/crypto/CLI capability that installs everywhere; no rapidgzip |
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
