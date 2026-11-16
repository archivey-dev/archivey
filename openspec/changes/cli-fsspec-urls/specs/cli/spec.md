## ADDED Requirements

### Requirement: CLI archive arguments accept fsspec URLs

Every CLI operation that opens an archive SHALL accept an archive URL through
fsspec, including default listing, aliases, `info`, and the `--outer` forms of
`cat`, `test` and `extract`.

#### Scenario: source resolution

- **WHEN** a CLI operation resolves its archive argument
- **THEN** source resolution SHALL use this order:

1. Preserve the existing empty-argument and stdin-token rules.
2. An existing local path SHALL take precedence over URL interpretation.
3. Otherwise, an argument beginning with a `scheme://` prefix known to fsspec
   SHALL become the unentered `OpenFile` returned by `fsspec.open(arg, mode="rb")`.
4. Other arguments SHALL retain their local-path interpretation, including
   Windows drive paths, UNC paths and unknown schemes.

The CLI MUST preserve the original URL for I/O, including its query, fragment and
escaping. It MUST NOT convert it to a `Path`, expand remote archive globs, request
fsspec decompression, or open the `OpenFile` before passing it to `open_archive`,
`detect_format` or `open_stream`. Archivey's remote-source contract SHALL govern
the reads, diagnostics, resource bounds and reader lifetime. Detection and opening
SHALL resolve the argument consistently, including `info`'s detection after a failed
open and detection for `--outer`. Remote sources MUST NOT use local existence or
file-type checks to decide whether detection can run again.

fsspec SHALL remain optional and be imported only when URL resolution needs it.
Local operations and CLI help MUST work without it. No dependency or extra SHALL
be added. Backend options and credentials SHALL use fsspec's normal defaults and
backend configuration. The CLI provides no storage-options syntax. The
library's string-source contract SHALL remain local-path-only.

An archive URL names one source as interpreted by fsspec. The CLI MUST NOT search
for remote volume siblings or provide a syntax for explicit remote volume lists.
Member patterns SHALL retain their existing meaning.

| Input | Result |
| --- | --- |
| Known URL, no existing local path | Unentered binary `OpenFile` passed to the public library API |
| Existing local path whose spelling starts with a known `scheme://` | Local archive, without importing fsspec |
| Unknown scheme, drive path, UNC path, or ordinary local path | Local-path behavior |
| URL containing `?`, `*` or brackets | One source, without CLI glob expansion |
| URL passed to `info` or an available `--outer` form | Same resolution rule as ordinary member operations |

### Requirement: Remote CLI inputs keep local extraction and safe display

Extraction destinations SHALL remain local, and CLI-authored URL labels SHALL
follow the library's remote-name policy before terminal escaping.

#### Scenario: URL names

- **WHEN** the CLI derives a destination or displays a URL label
- **THEN** it SHALL apply the following naming rules.

Without `-d`, smart extraction SHALL use the remote source's final filename with the
existing format-aware stem and collision rules. HTTP(S) queries and fragments and URL
authority credentials MUST NOT become part of the destination name. An absent or unsafe
stem SHALL use the existing `archive` fallback. URL escaping MUST NOT introduce a path
separator or traversal into a destination name.

CLI-authored labels, including `info`'s `path` field and `--outer` messages, SHALL
remove authority credentials and HTTP(S) queries and fragments before terminal
escaping. URL labels MUST NOT pass through local path normalization. This matches
the library's remote-name policy. Third-party exception text may still contain
the original URL, as documented by the remote-source error contract. Arbitrary
backend exception text is not guaranteed to be redacted.

| Case | Result |
| --- | --- |
| `https://host/data.tar.gz?signature=secret#part` needs a wrapper | Uses the local stem `data` under existing smart-extraction rules |
| `info` on a URL with authority credentials and an HTTP query | Prints the sanitized URL, with `://` preserved |
| No filename, or a filename whose stem is empty, `.` or `..` | Uses `archive` when a wrapper is needed |

### Requirement: CLI remote setup and transport failures are reported

Remote setup and transport failures SHALL produce terminal-safe CLI errors with
exit `1`, preserving existing partial-output behavior and exposing no traceback.
The CLI MUST NOT hide programming errors behind a catch-all exception handler.

#### Scenario: failed URL operation

- **WHEN** remote setup or transport fails
- **THEN** the CLI SHALL report the failure under these rules.

For a nonlocal URL candidate, missing fsspec SHALL cause exit `1` with an install
hint. A known protocol whose backend dependencies are missing SHALL likewise
cause exit `1` with an actionable dependency message, without falling back to a
local path. Missing remote objects, permission failures, connection failures,
unsupported range reads and `SourceChangedError` SHALL cause exit `1` with a
terminal-safe error and no traceback. A failure after partial output SHALL retain
the verb's existing partial-output and failure-reporting rules.

| Case | Result |
| --- | --- |
| Nonlocal `https://` argument without fsspec | Exit `1`, install hint, no traceback |
| Known protocol with missing backend package | Exit `1`, dependency message, no local retry |
| Transport fails or source changes during a member read | Exit `1`, existing partial-output behavior, no traceback |
