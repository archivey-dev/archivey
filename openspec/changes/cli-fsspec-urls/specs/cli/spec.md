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
3. Otherwise, a URL candidate SHALL trigger a lazy import of fsspec. A candidate
   begins with `[A-Za-z][A-Za-z0-9+.-]+://`, or is a `::` chain whose first link
   begins with that prefix or is a bare protocol matching
   `[A-Za-z][A-Za-z0-9+.-]+`. Schemes have at least two characters, so drive
   letters are not candidates. Matching SHALL be anchored at the argument's start.
   Missing fsspec SHALL cause the dependency failure below, for any candidate.
4. With fsspec installed, a candidate whose first protocol is registered with
   fsspec SHALL become the unentered `OpenFile` returned by
   `fsspec.open(arg, mode="rb")`. Bare first links such as `simplecache` name
   protocols in chains. Registration includes third-party registered protocols.
5. Other arguments SHALL retain their local-path interpretation, including
   Windows drive paths, UNC paths and, when fsspec is installed, unknown first
   protocols. A backend missing from a known protocol is a dependency failure,
   not an unknown protocol.

Chained URLs SHALL be accepted under fsspec's `::` syntax. Registered archive
protocols, including `zip`, `tar`, `libarchive` and `archivey`, SHALL be accepted as
sources too: the selected member's bytes become the CLI's archive input. The CLI
adds no separate nesting interpretation. Creating an `OpenFile` can itself do I/O
or fail while setting up an archive or cache filesystem; the same error rules
SHALL cover setup and later reads. The CLI MUST NOT enter the returned `OpenFile`.

The CLI MUST preserve the original URL for I/O, including its query, fragment and
escaping. It MUST NOT convert it to a `Path`, expand remote archive globs, request
fsspec decompression, or open the `OpenFile` before passing it to `open_archive`,
`detect_format` or `open_stream`. Archivey's remote-source contract SHALL govern
the reads, diagnostics, resource bounds and reader lifetime. Detection and opening
SHALL resolve the argument consistently, including `info`'s detection after a failed
open and detection for `--outer`. Remote sources MUST NOT use local existence or
file-type checks to decide whether detection can run again.

fsspec SHALL remain optional and be imported only when URL resolution needs it.
Local operations and CLI help MUST work without it. No runtime dependency or extra
SHALL be added. Backend options and credentials SHALL use fsspec's normal defaults and
backend configuration. The CLI provides no storage-options syntax. The
library's string-source contract SHALL remain local-path-only.

An archive URL names one source as interpreted by fsspec. The CLI MUST NOT search
for remote volume siblings or provide a syntax for explicit remote volume lists.
Member patterns SHALL retain their existing meaning.

| Input | Result |
| --- | --- |
| Known URL, no existing local path | Unentered binary `OpenFile` passed to the public library API |
| Existing local path whose spelling starts with a known `scheme://` | Local archive, without importing fsspec |
| `foo://x` with fsspec installed and `foo` unregistered | Local-path behavior |
| `foo://x` or `https://host/a.zip` without fsspec | Exit `1` with an install hint |
| Drive path, UNC path, or ordinary local path | Local-path behavior, without importing fsspec |
| `simplecache::https://host/a.zip` | Chained source through fsspec |
| `zip://inner.tar::memory://outer.zip` | Selected member is the archive input |
| URL containing `?`, `*` or brackets | One source, without CLI glob expansion |
| URL passed to `info` or an available `--outer` form | Same resolution rule as ordinary member operations |

### Requirement: Remote CLI inputs keep local extraction and safe display

Extraction destinations SHALL remain local, and CLI-authored URL labels SHALL
follow the library's remote-name policy before terminal escaping.

#### Scenario: URL names

- **WHEN** the CLI derives a destination or displays a URL label
- **THEN** it SHALL apply the following naming rules.

Without `-d`, smart extraction SHALL derive its filename from the URL path as
given, after removing authority credentials and, for HTTP(S), the query and
fragment. Take the last `/`-separated path segment without percent-decoding it.
Redirects and `Content-Disposition` MUST NOT determine the name. For a chain, use
the returned `OpenFile.path`, sanitized under the remote-name policy, and take its
last `/`-separated segment without percent-decoding. This names the selected
member for an archive filesystem and the target file for a cache filesystem.

Apply the existing format-aware stem stripping and collision rules, then check
that the stem is one safe local segment. An empty stem, `.` or `..`, any `/`, `\`
or `:`, control characters, or a name invalid on the destination OS SHALL use
`archive` instead. On Windows this includes reserved device names, `< > " | ? *`,
and trailing spaces or dots. The resulting name MUST NOT introduce a path root,
separator, traversal or alternate data stream. These URL-derived-name checks do
not change local-path naming.

CLI-authored labels, including `info`'s `path` field and `--outer` messages, SHALL
remove authority credentials and HTTP(S) queries and fragments before terminal
escaping. URL labels MUST NOT pass through local path normalization. This matches
the library's remote-name policy. For a chain, sanitize each URL-bearing link
separately and retain the chain separators. The CLI SHALL keep a local copy of
this display policy, pinned against the internal policy by tests, without adding
a public API name or importing internal helpers into CLI code.

Before emitting third-party exception text, including through CLI logging, the
CLI SHALL replace every exact occurrence of the original argument and its
URL-bearing chain links with their sanitized labels, longest strings first.
Perform substitution before terminal escaping. For `aiohttp.ClientResponseError`
the CLI SHALL NOT print the exception text, because aiohttp re-encodes the
request URL (for example `%2F` becomes `/`) and exact substitution then misses
it. The CLI SHALL build that message itself from the exception's `status` and
`message` and the sanitized label. Any other backend that transforms or
re-encodes a URL, or prints credentials separately, is not guaranteed to be
redacted. Library exception propagation remains unchanged.

| Case | Result |
| --- | --- |
| `https://host/data.tar.gz?signature=secret#part` needs a wrapper | Uses the local stem `data` under existing smart-extraction rules |
| `info` on a URL with authority credentials and an HTTP query | Prints the sanitized URL, with `://` preserved |
| No filename, or a filename whose stem is empty, `.` or `..` | Uses `archive` when a wrapper is needed |
| HTTP filename `..\..\x.tar.gz` | Uses `archive`, including on Windows |
| S3 filename `a:b.tar.gz`, or Windows filename `a?b*.tar.gz` | Uses `archive` |
| HTTP filename `a%20b.tar.gz` or `%5C.tar.gz` | Uses literal `a%20b` or `%5C`, without decoding |
| HTTP 404 whose error contains the exact signed URL argument | Shows the sanitized URL, without the signature |

### Requirement: CLI remote setup and transport failures are reported

The handled remote setup and transport exceptions below SHALL produce
terminal-safe CLI errors with exit `1`, preserving existing partial-output
behavior and exposing no traceback. Other exceptions SHALL propagate unchanged.
The CLI MUST NOT hide programming errors behind a catch-all exception handler.

#### Scenario: failed URL operation

- **WHEN** remote setup or transport fails
- **THEN** the CLI SHALL report the failure under these rules.

For a nonlocal URL candidate, missing fsspec SHALL cause exit `1` with an install
hint. A known protocol whose backend dependencies are missing SHALL likewise
cause exit `1` with an actionable dependency message, without falling back to a
local path. Catch dependency `ImportError` only while importing fsspec or
constructing its filesystem/`OpenFile`. Existing `ArchiveyError` and `OSError`
handling covers missing objects, OS-level permission and connection failures,
unsupported range responses rejected by archivey, and `SourceChangedError`.

For HTTP(S), also handle `aiohttp.ClientError`, imported only when its package is
loaded by the backend. The default `http`/`https` backend uses aiohttp only, so no
`requests` exception is handled. The handled exceptions SHALL be recognized during setup,
detection, opening and member iteration, including HTTP layers inside chains.
The CLI MUST NOT catch arbitrary `ValueError`, `RuntimeError` or `Exception` as
transport failures. Non-HTTP backends retain the shared `OSError` handling;
backend-specific exceptions outside this list can produce a traceback. A failure
after partial output SHALL retain the verb's existing failure-reporting rules.

| Case | Result |
| --- | --- |
| Nonlocal `https://` argument without fsspec | Exit `1`, install hint, no traceback |
| Known protocol with missing backend package | Exit `1`, dependency message, no local retry |
| HTTP 403 at setup or during a member read | Exit `1`, no traceback, sanitized URL in the error |
| Handled transport exception or `SourceChangedError` during a member read | Exit `1`, existing partial-output behavior, no traceback |
| Unlisted backend exception or programming error | Propagates unchanged |
