# diagnostics — format policy delta

## MODIFIED Requirements

### Requirement: Report unused explicit arguments as diagnostics

When an explicit argument is a **resource offered for use if needed** rather than an
assertion about the archive (see `archive-reading`), `open_archive()` SHALL accept it
and, when the resolved backend cannot act on it, SHALL emit one diagnostic naming the
argument. It MUST NOT raise.

| Condition | Code | `reason` |
| --- | --- | --- |
| Caller passed `encoding=` and `ReadBackend.USES_ENCODING` is `False` | `ENCODING_ARGUMENT_UNUSED` | why the backend decodes names another way, or that a replacement reader (`FormatPolicy(replace=)`) does not apply one |
| Caller passed a concrete `password=` (a single value or a sequence) and `ReadBackend.SUPPORTS_PASSWORD` is `False` | `PASSWORD_ARGUMENT_UNUSED` | that the format carries no encryption, or that a replacement reader takes no password |

Each SHALL be emitted **at most once per `open_archive()` call**, before the reader is
returned, so a caller can inspect `reader.diagnostics` without listing anything.

`password=` SHALL open identically in all three forms (a single value, a sequence of
candidates, a provider callable) on a format with no encryption: accepted, never
consulted. A single value or a sequence SHALL record one diagnostic. A provider callable
SHALL record none: it offers a password only if asked, and a format with no encryption
never asks, so no password was supplied. (The CLI passes a provider on every run.) A
wrong password on an *encrypted* archive is unaffected and still raises.

#### Scenario: unused argument matrix

| Case | Expected |
| --- | --- |
| `open_archive(sevenzip, encoding="cp500")` | Opens; one `ENCODING_ARGUMENT_UNUSED`; names unchanged |
| `open_archive(iso, encoding="cp500")` | No diagnostic; UTF-8 names unchanged, and the encoding applies to a Rock Ridge or plain name that is not valid UTF-8 |
| `open_archive(zip, encoding="cp500")` | No diagnostic; UTF-8 names unchanged, and the encoding applies to an unflagged name that is not valid UTF-8 |
| Auto-detected open with no `encoding=` on a backend that ignores encoding | No diagnostic |
| `open_archive(tar, password="p")` / `password=["a","b"]` | Both open; one `PASSWORD_ARGUMENT_UNUSED` each; no `ArchiveyUsageError` |
| `open_archive(tar \| gz \| directory, password=lambda r: "p")` | Opens; no `PASSWORD_ARGUMENT_UNUSED`; the provider is never called |
| `open_archive(zip, password="p")` with ZIP replaced by a plugin | Opens; one `PASSWORD_ARGUMENT_UNUSED` whose message and `reason` name the replacement reader, not the format |
| Wrong password on an encrypted ZIP | Unchanged: `EncryptionError` |
