# tar-minefield results

<!-- Written by scripts/gen_tar_minefield_expected.py; edit the reasons in
tests/test_tar_minefield_corpus.py and rerun it. -->

Archivey's TAR reader against the [tar-minefield](https://stoppels.ch/tar/) corpus ([source](https://github.com/haampie/tar-minefield) at `104b4bab`), next to GNU tar 1.35 and Astral's tar-codec, as the corpus's own matrix gives them. `tests/test_tar_minefield_corpus.py` runs it; its docstring says how. Each case links to its page on the corpus's site.

Archivey runs each case three ways:

- **TRUSTED**: `ExtractionPolicy.TRUSTED`, `overwrite=REPLACE`, the closest to `tar -x`.
- **STRICT**: `ExtractionPolicy.STRICT`, `overwrite=REPLACE`, with the default `DiagnosticPolicy`, which reports the odd framing shapes but reads them. It fails more cases than Safest for that reason.
- **Safest** (STRICT + DiagnosticPolicy.STRICT): the default `ExtractionPolicy.STRICT` and `overwrite=ERROR`, with `DiagnosticPolicy.STRICT`, which refuses every shape in `ARCHIVE_INTEGRITY_CODES`. It is held to tar-codec's bar: every case it fails has a reason below.

An outcome is `expected` (the case's tree), `rejected` (the open failed or a member was not written, an unavailable link target included) or `other` (another tree). A `reject` case passes only when rejected, a `tolerate` case when rejected or expected, an `accept` case only when expected. In the tables ✅ passes and ❌ fails the case's verdict; ≠GNU marks a TRUSTED or STRICT run whose result is not GNU tar's (its tree, or a refusal where GNU tar refuses). No case writes outside the destination: the test fails if one does.

Each case below gives a reason per run that owes one: Safest wherever it fails the verdict, TRUSTED wherever it fails it or is not GNU tar's result, and STRICT only where TRUSTED's reason does not cover it.

## Summary

| Run | Passes | GNU tar's result |
| --- | --- | --- |
| TRUSTED | 40 of 81 | 78 of 81 |
| STRICT | 40 of 81 | 71 of 81 |
| Safest (STRICT + DiagnosticPolicy.STRICT) | 67 of 81 | not compared |
| GNU tar 1.35 | 40 of 81 | |
| tar-codec | 68 of 81 | |

## Cases the safest settings fail

The safety bar: each case STRICT + DiagnosticPolicy.STRICT fails, 🔴 where tar-codec passes it and 🟡 where tar-codec fails it too, with why Archivey reads it rather than refusing it. The reasons for the other runs follow where they have their own.

### Framing

Where a member's data ends and which headers belong to it. A shape no real writer produces should be a diagnostic in ARCHIVE_INTEGRITY_CODES, which DiagnosticPolicy.STRICT refuses, unless well justified.

#### F16-type-unknown

🔴 [F16](https://stoppels.ch/tar/F16.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ❌ other.

- **Safest**: MEMBER_TYPE_UNKNOWN is deliberately out of DiagnosticPolicy.STRICT: real writers emit vendor typeflags with data (Solaris tar's X extended headers and A ACLs), GNU tar extracts them as files, and Archivey delivers the data as a FILE, so nothing is hidden
- **TRUSTED**: Extracted as GNU tar extracts it (DR-6): an unknown typeflag with data is a file, as GNU tar extracts it, reported with MEMBER_TYPE_UNKNOWN (maintainer ruling 2026-10-17)

### Names

Which field names a member, and how a path is normalized. A name another OS or reader takes differently should be blocked by ExtractionPolicy.STRICT.

#### N10-format-star

🟡 [N10](https://stoppels.ch/tar/N10.html), reject: GNU tar ❌ other, tar-codec ❌ other, TRUSTED ❌ other, STRICT ❌ other, Safest ❌ other.

- **Safest**: star writes this format (berkeley-db 18.1.40, ncurses 5.9); under the POSIX magic the whole field is the prefix, as GNU tar reads it
- **TRUSTED**: Extracted as GNU tar extracts it (DR-6): under the POSIX magic the whole prefix field is the name prefix. Not reported: star writes this format (berkeley-db, ncurses)
- **STRICT**: STRICT rewrites the name to a spelling every OS can hold (ADR 0013): the trailing blank is dropped

#### N11-gnu-prefix-field

🟡 [N11](https://stoppels.ch/tar/N11.html), reject: GNU tar ❌ other, tar-codec ❌ other, TRUSTED ❌ other, STRICT ❌ other, Safest ❌ other.

- **Safest**: GNU tar's incremental archives put times in those bytes; under the GNU magic they are never a prefix
- **TRUSTED**: Extracted as GNU tar extracts it (DR-6): under the GNU magic those bytes are not a prefix. Not reported: GNU tar writes times there in incremental archives

#### N13-name-backslash

🔴 [N13](https://stoppels.ch/tar/N13.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ❌ other.

- **Safest**: STRICT writes the name in a spelling every OS can hold (ADR 0013) instead of refusing it, so the tree is not the expected one, but nothing lands outside the destination or under a name another OS reads differently: the backslash is a separator
- **TRUSTED**: TRUSTED keeps a backslash as a character, as GNU tar on POSIX does. Not reported: texi2html and gstreamer-docs tarballs have them
- **STRICT**: STRICT rewrites the name to a spelling every OS can hold (ADR 0013): the backslash is a separator

#### N15-name-control-character

🔴 [N15](https://stoppels.ch/tar/N15.html), tolerate: GNU tar ✅ expected, tar-codec ✅ rejected, TRUSTED ✅ expected, STRICT ❌ other, Safest ❌ other.

- **Safest**: STRICT writes the name in a spelling every OS can hold (ADR 0013) instead of refusing it, so the tree is not the expected one, but nothing lands outside the destination or under a name another OS reads differently: the newline becomes %0A
- **STRICT**: STRICT rewrites the name to a spelling every OS can hold (ADR 0013): the newline becomes %0A

#### N18-name-not-utf8

🔴 [N18](https://stoppels.ch/tar/N18.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ❌ other.

- **Safest**: STRICT writes the name in a spelling every OS can hold (ADR 0013) instead of refusing it, so the tree is not the expected one, but nothing lands outside the destination or under a name another OS reads differently: the byte 0xE9 becomes %E9
- **TRUSTED**: TRUSTED writes the name's bytes, as GNU tar does. Not reported: aspell tarballs have Latin-1 names
- **STRICT**: STRICT rewrites the name to a spelling every OS can hold (ADR 0013): the byte 0xE9 becomes %E9

#### N24-pax-hdrcharset-binary

🔴 [N24](https://stoppels.ch/tar/N24.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ❌ other.

- **Safest**: STRICT writes the name in a spelling every OS can hold (ADR 0013) instead of refusing it, so the tree is not the expected one, but nothing lands outside the destination or under a name another OS reads differently: the byte 0xE9 becomes %E9
- **TRUSTED**: TRUSTED writes the name's bytes, as GNU tar does. Not reported: hdrcharset=BINARY is POSIX's way to store them, and readers disagree only on whether to write or skip the file, not on its name
- **STRICT**: STRICT rewrites the name to a spelling every OS can hold (ADR 0013): the byte 0xE9 becomes %E9

### Kinds

Whether a member is a file, directory or link. Mixed: decided case by case.

#### K01-kind-trailing-slash-file

🔴 [K01](https://stoppels.ch/tar/K01.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ❌ other.

- **Safest**: v7 tarballs (sendmail 8.18.2, tcp_wrappers 7.6) store directories this way, and GNU tar makes it a directory; refusing it refuses real archives
- **TRUSTED**: Extracted as GNU tar extracts it (DR-6): a regular file named a/ is a directory, as GNU tar's extract.c makes it. Not reported: v7 tarballs (sendmail, tcp_wrappers) store directories this way

#### K02-linkname-on-file

🟡 [K02](https://stoppels.ch/tar/K02.html), reject: GNU tar ❌ other, tar-codec ❌ other, TRUSTED ❌ other, STRICT ❌ other, Safest ❌ other.

- **Safest**: bgen 1.1.7 writes it, and the link name of a regular file is never used: only a reader that ignores the typeflag makes a link
- **TRUSTED**: Extracted as GNU tar extracts it (DR-6): a regular file's link name is not used. Not reported: bgen 1.1.7 writes one, and only a reader that goes by the link name reads a link

### Order and state

Duplicate paths and links between members. Mixed: decided case by case.

#### S04-hardlink-to-itself

🔴 [S04](https://stoppels.ch/tar/S04.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ❌ other.

- **Safest**: 27 real tarballs have it (cuDNN binaries in Spack, xscreensaver 6.12); the file stays as it is
- **TRUSTED**: Extracted as GNU tar extracts it (DR-6): the file stays as it is; 27 real tarballs have the shape

#### S06-hardlink-to-symlink

🔴 [S06](https://stoppels.ch/tar/S06.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ❌ other.

- **Safest**: octa 8.4 has it; the hard link is a second symlink to the same target, checked like the first, never followed
- **TRUSTED**: Extracted as GNU tar extracts it (DR-6): the hard link is a second link to the symlink, not to its target

#### S07-tree-duplicate-file-differs

🟡 [S07](https://stoppels.ch/tar/S07.html), reject: GNU tar ❌ other, tar-codec ❌ other, TRUSTED ❌ other, STRICT ❌ other, Safest ❌ other.

- **Safest**: fish 4.7.1 has it: a later file supersedes an earlier file of the same name, as with tar -x, under every OverwritePolicy. A later member that changes the kind at that name (S08, a directory after a file) is not a supersede and goes through overwrite=ERROR, which refuses it
- **TRUSTED**: Extracted as GNU tar extracts it (DR-6): OverwritePolicy.REPLACE, as tar -x, lets the later member win, and the shape is in real tarballs. overwrite=ERROR, the default, refuses the second member instead

#### S09-tree-duplicate-file-identical

🟡 [S09](https://stoppels.ch/tar/S09.html), reject: GNU tar ❌ other, tar-codec ❌ other, TRUSTED ❌ other, STRICT ❌ other, Safest ❌ other.

- **Safest**: cabal sdist tarballs have it; the later copy supersedes the earlier one, as for S07
- **TRUSTED**: Extracted as GNU tar extracts it (DR-6): OverwritePolicy.REPLACE, as tar -x, lets the later member win, and the shape is in real tarballs. overwrite=ERROR, the default, refuses the second member instead

#### S10-tree-symlink-then-file

🟡 [S10](https://stoppels.ch/tar/S10.html), reject: GNU tar ❌ other, tar-codec ❌ other, TRUSTED ❌ other, STRICT ❌ other, Safest ❌ other.

- **Safest**: The file supersedes the link, as for S07, and is never written through it: the link is replaced, so the write stays in the destination
- **TRUSTED**: Extracted as GNU tar extracts it (DR-6): OverwritePolicy.REPLACE, as tar -x, lets the later member win, and the shape is in real tarballs. overwrite=ERROR, the default, refuses the second member instead. The file replaces the link, never writing through it

## Other cases TRUSTED or STRICT fails or reads unlike GNU tar

Cases the safest settings pass, but where TRUSTED or STRICT fails the verdict or does not give GNU tar's result. TRUSTED and STRICT only report the framing shapes DiagnosticPolicy.STRICT refuses, so they pass fewer cases.

### Framing

Where a member's data ends and which headers belong to it. A shape no real writer produces should be a diagnostic in ARCHIVE_INTEGRITY_CODES, which DiagnosticPolicy.STRICT refuses, unless well justified.

#### F03-end-lone-zero-block

[F03](https://stoppels.ch/tar/F03.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), reported with ARCHIVE_EOF_MARKER_MISSING: real tarballs end this way, and the members before the block are whole

#### F06-checksum-signed

[F06](https://stoppels.ch/tar/F06.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (signed_checksum): GNU tar accepts a header that matches either the unsigned or the signed sum; SunOS 4 and Ultrix tars wrote the signed one, no current writer does

#### F07-end-archive-after

[F07](https://stoppels.ch/tar/F07.html), reject: GNU tar ❌ other, tar-codec ❌ other, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), reported with ARCHIVE_TRAILING_DATA: what follows the end marker is not read, as GNU tar does not read it

#### F09-end-zero-block-then-member

[F09](https://stoppels.ch/tar/F09.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), reported with ARCHIVE_EOF_MARKER_MISSING and ARCHIVE_TRAILING_DATA: the zero block ends the archive, as in GNU tar without --ignore-zeros

#### F10-extended-pax-size-before-gnu-long

[F10](https://stoppels.ch/tar/F10.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (mixed_chain)

#### F11-magic-odd-version

[F11](https://stoppels.ch/tar/F11.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (magic_version): GNU tar reads any POSIX magic as ustar, whatever the version

#### F12-number-size-gap

[F12](https://stoppels.ch/tar/F12.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (field_tail): the size ends at the blank, as in GNU tar

#### F13-pax-newline-in-path

[F13](https://stoppels.ch/tar/F13.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (newline_in_value): a record is framed by its length, as POSIX says, so the newline is a byte of the path. Newlines in xattr and ACL values are real and not reported
- **STRICT**: STRICT rewrites the name to a spelling every OS can hold (ADR 0013): the newline becomes %0A

#### F15-pax-size-on-dir

[F15](https://stoppels.ch/tar/F15.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Not the corpus's GNU tar column, which reads the header after the directory as dir/smuggled: that is upstream GNU tar 1.35, before the fix for CVE-2026-5704 (a member injected past a directory's data). The patched GNU tar 1.35 (Ubuntu 1.35+dfsg-3ubuntu0.4, measured 2026-10-30) skips the blocks the PAX size declares and writes the directory alone, and so does Archivey, reporting MEMBER_DIRECTORY_DATA_IGNORED. Listing and extraction agree on one member either way

#### F19-pax-global-between-extended-and-member

[F19](https://stoppels.ch/tar/F19.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (global_in_chain)

#### F20-pax-global-size

[F20](https://stoppels.ch/tar/F20.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (global_member_field)

#### F26-pax-size-leading-zero

[F26](https://stoppels.ch/tar/F26.html), reject: GNU tar ❌ other, tar-codec ❌ other, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (leading_zero): the size is decimal, as POSIX and GNU tar read it

#### F28-pax-newline-in-comment

[F28](https://stoppels.ch/tar/F28.html), reject: GNU tar ❌ other, tar-codec ❌ other, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (newline_in_value): the newline cannot start a size record, as for F13

#### F33-size-on-dir

[F33](https://stoppels.ch/tar/F33.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (size_on_no_data): the next header is read, as GNU tar reads it (maintainer ruling 2026-10-30 to report it)

#### F34-size-on-hardlink

[F34](https://stoppels.ch/tar/F34.html), reject: GNU tar ❌ other, tar-codec ❌ other, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (size_on_no_data)

#### F35-pax-size-on-hardlink

[F35](https://stoppels.ch/tar/F35.html), reject: GNU tar ❌ other, tar-codec ❌ other, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Not the corpus's GNU tar column, which reads the header after the link as smuggled: Archivey skips the blocks the PAX size declares, as the CVE-2026-5704-patched GNU tar 1.35 does (F15), and reports MEMBER_LINK_DATA_IGNORED

### Names

Which field names a member, and how a path is normalized. A name another OS or reader takes differently should be blocked by ExtractionPolicy.STRICT.

#### N07-symlink-absolute

[N07](https://stoppels.ch/tar/N07.html), tolerate: GNU tar ✅ expected, tar-codec ✅ rejected, TRUSTED ✅ rejected, STRICT ✅ rejected, Safest ✅ rejected.

- **TRUSTED**: Refused under every policy: an absolute symlink target leads outside the destination, which no ExtractionPolicy writes (GNU tar writes the link as stored). The corpus tolerates a refusal

#### N08-extended-pax-path-and-gnu-long-name

[N08](https://stoppels.ch/tar/N08.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (both_families): the PAX path wins, as in GNU tar

#### N09-extended-two-pax-headers

[N09](https://stoppels.ch/tar/N09.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (repeated): the last x header wins, as in GNU tar

#### N12-name-absolute

[N12](https://stoppels.ch/tar/N12.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ✅ rejected, Safest ✅ rejected.

- **TRUSTED**: TRUSTED re-roots an absolute name inside the destination, as GNU tar strips the leading slash. Nothing is written outside it
- **STRICT**: STRICT refuses an absolute name (ADR 0013)

#### N14-name-bytes-after-nul

[N14](https://stoppels.ch/tar/N14.html), reject: GNU tar ❌ other, tar-codec ❌ other, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (field_tail): the name ends at the NUL, as in GNU tar

#### N19-pax-nul-in-path

[N19](https://stoppels.ch/tar/N19.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (nul_in_value): the value ends at the NUL, as in GNU tar

#### N20-pax-repeated-key

[N20](https://stoppels.ch/tar/N20.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (repeated): the last record wins in an x header, as in GNU tar

#### N21-pax-global-path

[N21](https://stoppels.ch/tar/N21.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (global_member_field)

#### N22-pax-path-empty

[N22](https://stoppels.ch/tar/N22.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (empty_value): the empty path is skipped and the header's name stays, as in GNU tar

#### N23-extended-gnu-long-then-pax

[N23](https://stoppels.ch/tar/N23.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (mixed_chain)

#### N26-pax-global-path-then-empty

[N26](https://stoppels.ch/tar/N26.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6), and reported with MEMBER_HEADER_AMBIGUOUS, since no real writer produces the shape and another reader can frame or name it differently (global_member_field, global_replaced): each g header replaces the global records before it, as in GNU tar

### Kinds

Whether a member is a file, directory or link. Mixed: decided case by case.

#### K03-symlink-trailing-slash

[K03](https://stoppels.ch/tar/K03.html), reject: GNU tar ❌ other, tar-codec ✅ rejected, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6): the trailing slash is dropped, reported with MEMBER_NAME_NORMALIZED

### Order and state

Duplicate paths and links between members. Mixed: decided case by case.

#### S08-tree-duplicate-file-dir

[S08](https://stoppels.ch/tar/S08.html), reject: GNU tar ❌ other, tar-codec ❌ other, TRUSTED ❌ other, STRICT ❌ other, Safest ✅ rejected.

- **TRUSTED**: Extracted as GNU tar extracts it (DR-6): OverwritePolicy.REPLACE, as tar -x, lets the later member win, and the shape is in real tarballs. overwrite=ERROR, the default, refuses the second member instead

## Cases Safest refuses that GNU tar extracts

A refusal passes a `reject` or `tolerate` case, 71 of 81, so the pass counts bound how permissive a run is, not how strict. These are the cases where Safest refuses and GNU tar writes the expected tree: the cost of the safety bar. The code is what the listing reports.

- [F02](https://stoppels.ch/tar/F02.html) `F02-end-data-after` (tolerate; tar-codec expected): `archive_trailing_data`
- [F04](https://stoppels.ch/tar/F04.html) `F04-end-missing` (tolerate; tar-codec rejected): `archive_eof_marker_missing`
- [N06](https://stoppels.ch/tar/N06.html) `N06-name-leading-dot-slash` (tolerate; tar-codec expected): `member_name_normalized`
- [N07](https://stoppels.ch/tar/N07.html) `N07-symlink-absolute` (tolerate; tar-codec rejected): nothing reported

## Every case

Why links to the case's entry above, for a case where any run fails the verdict or a TRUSTED or STRICT run is not GNU tar's result.

| Case | Verdict | GNU tar | tar-codec | TRUSTED | STRICT | Safest | Listing reports | Why |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [F01](https://stoppels.ch/tar/F01.html) `number-leading-space` | tolerate | ✅ expected | ✅ rejected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [F02](https://stoppels.ch/tar/F02.html) `end-data-after` | tolerate | ✅ expected | ✅ expected | ✅ expected | ✅ expected | ✅ rejected | `archive_trailing_data` |  |
| [F03](https://stoppels.ch/tar/F03.html) `end-lone-zero-block` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `archive_eof_marker_missing` | [why](#f03-end-lone-zero-block) |
| [F04](https://stoppels.ch/tar/F04.html) `end-missing` | tolerate | ✅ expected | ✅ rejected | ✅ expected | ✅ expected | ✅ rejected | `archive_eof_marker_missing` |  |
| [F05](https://stoppels.ch/tar/F05.html) `magic-version-nuls` | tolerate | ✅ expected | ✅ rejected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [F06](https://stoppels.ch/tar/F06.html) `checksum-signed` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#f06-checksum-signed) |
| [F07](https://stoppels.ch/tar/F07.html) `end-archive-after` | reject | ❌ other | ❌ other | ❌ other | ❌ other | ✅ rejected | `archive_trailing_data` | [why](#f07-end-archive-after) |
| [F08](https://stoppels.ch/tar/F08.html) `end-truncated-in-member` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | `error: TruncatedError` |  |
| [F09](https://stoppels.ch/tar/F09.html) `end-zero-block-then-member` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `archive_eof_marker_missing`, `archive_trailing_data` | [why](#f09-end-zero-block-then-member) |
| [F10](https://stoppels.ch/tar/F10.html) `extended-pax-size-before-gnu-long` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#f10-extended-pax-size-before-gnu-long) |
| [F11](https://stoppels.ch/tar/F11.html) `magic-odd-version` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#f11-magic-odd-version) |
| [F12](https://stoppels.ch/tar/F12.html) `number-size-gap` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#f12-number-size-gap) |
| [F13](https://stoppels.ch/tar/F13.html) `pax-newline-in-path` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other ≠GNU | ✅ rejected | `member_header_ambiguous` | [why](#f13-pax-newline-in-path) |
| [F14](https://stoppels.ch/tar/F14.html) `pax-size-disagrees` | tolerate | ✅ expected | ✅ expected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [F15](https://stoppels.ch/tar/F15.html) `pax-size-on-dir` | reject | ❌ other | ✅ rejected | ❌ other ≠GNU | ❌ other ≠GNU | ✅ rejected | `member_directory_data_ignored` | [why](#f15-pax-size-on-dir) |
| [F16](https://stoppels.ch/tar/F16.html) `type-unknown` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ❌ other | `member_type_unknown` | [why](#f16-type-unknown) |
| [F17](https://stoppels.ch/tar/F17.html) `pax-global-comment` | accept | ✅ expected | ✅ expected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [F18](https://stoppels.ch/tar/F18.html) `pax-global-comment-after-members` | tolerate | ✅ expected | ✅ expected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [F19](https://stoppels.ch/tar/F19.html) `pax-global-between-extended-and-member` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#f19-pax-global-between-extended-and-member) |
| [F20](https://stoppels.ch/tar/F20.html) `pax-global-size` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#f20-pax-global-size) |
| [F21](https://stoppels.ch/tar/F21.html) `pax-size-empty` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | `error: CorruptionError` |  |
| [F22](https://stoppels.ch/tar/F22.html) `pax-size-negative` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | `error: CorruptionError` |  |
| [F23](https://stoppels.ch/tar/F23.html) `pax-size-plus` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | `error: CorruptionError` |  |
| [F24](https://stoppels.ch/tar/F24.html) `pax-size-leading-space` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | `error: CorruptionError` |  |
| [F25](https://stoppels.ch/tar/F25.html) `pax-size-not-ascii-digits` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | `error: CorruptionError` |  |
| [F26](https://stoppels.ch/tar/F26.html) `pax-size-leading-zero` | reject | ❌ other | ❌ other | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#f26-pax-size-leading-zero) |
| [F27](https://stoppels.ch/tar/F27.html) `pax-size-too-large` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | `error: CorruptionError` |  |
| [F28](https://stoppels.ch/tar/F28.html) `pax-newline-in-comment` | reject | ❌ other | ❌ other | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#f28-pax-newline-in-comment) |
| [F29](https://stoppels.ch/tar/F29.html) `number-size-base256-negative` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | `error: CorruptionError` |  |
| [F30](https://stoppels.ch/tar/F30.html) `number-size-base256-too-large` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | `error: CorruptionError` |  |
| [F31](https://stoppels.ch/tar/F31.html) `pax-xattr-not-utf8` | accept | ✅ expected | ✅ expected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [F32](https://stoppels.ch/tar/F32.html) `checksum-leading-space` | tolerate | ✅ expected | ✅ rejected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [F33](https://stoppels.ch/tar/F33.html) `size-on-dir` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#f33-size-on-dir) |
| [F34](https://stoppels.ch/tar/F34.html) `size-on-hardlink` | reject | ❌ other | ❌ other | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#f34-size-on-hardlink) |
| [F35](https://stoppels.ch/tar/F35.html) `pax-size-on-hardlink` | reject | ❌ other | ❌ other | ❌ other ≠GNU | ❌ other ≠GNU | ✅ rejected | `member_link_data_ignored` | [why](#f35-pax-size-on-hardlink) |
| [F36](https://stoppels.ch/tar/F36.html) `pax-record-length-short` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | `error: CorruptionError` |  |
| [F37](https://stoppels.ch/tar/F37.html) `number-size-not-octal` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | `error: CorruptionError` |  |
| [K01](https://stoppels.ch/tar/K01.html) `kind-trailing-slash-file` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ❌ other | nothing | [why](#k01-kind-trailing-slash-file) |
| [K02](https://stoppels.ch/tar/K02.html) `linkname-on-file` | reject | ❌ other | ❌ other | ❌ other | ❌ other | ❌ other | nothing | [why](#k02-linkname-on-file) |
| [K03](https://stoppels.ch/tar/K03.html) `symlink-trailing-slash` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_name_normalized` | [why](#k03-symlink-trailing-slash) |
| [N01](https://stoppels.ch/tar/N01.html) `gnu-long-name` | accept | ✅ expected | ✅ expected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [N02](https://stoppels.ch/tar/N02.html) `name-fills-field` | accept | ✅ expected | ✅ expected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [N03](https://stoppels.ch/tar/N03.html) `pax-long-name` | accept | ✅ expected | ✅ expected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [N04](https://stoppels.ch/tar/N04.html) `ustar-prefix` | accept | ✅ expected | ✅ expected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [N05](https://stoppels.ch/tar/N05.html) `name-dot` | tolerate | ✅ expected | ✅ expected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [N06](https://stoppels.ch/tar/N06.html) `name-leading-dot-slash` | tolerate | ✅ expected | ✅ expected | ✅ expected | ✅ expected | ✅ rejected | `member_name_normalized` |  |
| [N07](https://stoppels.ch/tar/N07.html) `symlink-absolute` | tolerate | ✅ expected | ✅ rejected | ✅ rejected ≠GNU | ✅ rejected ≠GNU | ✅ rejected | nothing | [why](#n07-symlink-absolute) |
| [N08](https://stoppels.ch/tar/N08.html) `extended-pax-path-and-gnu-long-name` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#n08-extended-pax-path-and-gnu-long-name) |
| [N09](https://stoppels.ch/tar/N09.html) `extended-two-pax-headers` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#n09-extended-two-pax-headers) |
| [N10](https://stoppels.ch/tar/N10.html) `format-star` | reject | ❌ other | ❌ other | ❌ other | ❌ other ≠GNU | ❌ other | nothing | [why](#n10-format-star) |
| [N11](https://stoppels.ch/tar/N11.html) `gnu-prefix-field` | reject | ❌ other | ❌ other | ❌ other | ❌ other | ❌ other | nothing | [why](#n11-gnu-prefix-field) |
| [N12](https://stoppels.ch/tar/N12.html) `name-absolute` | reject | ❌ other | ✅ rejected | ❌ other | ✅ rejected ≠GNU | ✅ rejected | nothing | [why](#n12-name-absolute) |
| [N13](https://stoppels.ch/tar/N13.html) `name-backslash` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other ≠GNU | ❌ other | nothing | [why](#n13-name-backslash) |
| [N14](https://stoppels.ch/tar/N14.html) `name-bytes-after-nul` | reject | ❌ other | ❌ other | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#n14-name-bytes-after-nul) |
| [N15](https://stoppels.ch/tar/N15.html) `name-control-character` | tolerate | ✅ expected | ✅ rejected | ✅ expected | ❌ other ≠GNU | ❌ other | nothing | [why](#n15-name-control-character) |
| [N16](https://stoppels.ch/tar/N16.html) `name-dotdot` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | nothing |  |
| [N17](https://stoppels.ch/tar/N17.html) `name-empty` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | `member_name_normalized` |  |
| [N18](https://stoppels.ch/tar/N18.html) `name-not-utf8` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other ≠GNU | ❌ other | nothing | [why](#n18-name-not-utf8) |
| [N19](https://stoppels.ch/tar/N19.html) `pax-nul-in-path` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#n19-pax-nul-in-path) |
| [N20](https://stoppels.ch/tar/N20.html) `pax-repeated-key` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#n20-pax-repeated-key) |
| [N21](https://stoppels.ch/tar/N21.html) `pax-global-path` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#n21-pax-global-path) |
| [N22](https://stoppels.ch/tar/N22.html) `pax-path-empty` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#n22-pax-path-empty) |
| [N23](https://stoppels.ch/tar/N23.html) `extended-gnu-long-then-pax` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#n23-extended-gnu-long-then-pax) |
| [N24](https://stoppels.ch/tar/N24.html) `pax-hdrcharset-binary` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other ≠GNU | ❌ other | nothing | [why](#n24-pax-hdrcharset-binary) |
| [N25](https://stoppels.ch/tar/N25.html) `symlink-empty-target` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | `symlink_target_unavailable` |  |
| [N26](https://stoppels.ch/tar/N26.html) `pax-global-path-then-empty` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ✅ rejected | `member_header_ambiguous` | [why](#n26-pax-global-path-then-empty) |
| [N27](https://stoppels.ch/tar/N27.html) `pax-long-symlink` | accept | ✅ expected | ✅ expected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [N28](https://stoppels.ch/tar/N28.html) `pax-long-hardlink` | accept | ✅ expected | ✅ expected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [S01](https://stoppels.ch/tar/S01.html) `tree-dir-after-contents` | accept | ✅ expected | ✅ expected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [S02](https://stoppels.ch/tar/S02.html) `tree-duplicate-dir` | accept | ✅ expected | ✅ expected | ✅ expected | ✅ expected | ✅ expected | nothing |  |
| [S03](https://stoppels.ch/tar/S03.html) `hardlink-missing-target` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | nothing |  |
| [S04](https://stoppels.ch/tar/S04.html) `hardlink-to-itself` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ❌ other | nothing | [why](#s04-hardlink-to-itself) |
| [S05](https://stoppels.ch/tar/S05.html) `hardlink-to-later-member` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | nothing |  |
| [S06](https://stoppels.ch/tar/S06.html) `hardlink-to-symlink` | reject | ❌ other | ✅ rejected | ❌ other | ❌ other | ❌ other | nothing | [why](#s06-hardlink-to-symlink) |
| [S07](https://stoppels.ch/tar/S07.html) `tree-duplicate-file-differs` | reject | ❌ other | ❌ other | ❌ other | ❌ other | ❌ other | nothing | [why](#s07-tree-duplicate-file-differs) |
| [S08](https://stoppels.ch/tar/S08.html) `tree-duplicate-file-dir` | reject | ❌ other | ❌ other | ❌ other | ❌ other | ✅ rejected | nothing | [why](#s08-tree-duplicate-file-dir) |
| [S09](https://stoppels.ch/tar/S09.html) `tree-duplicate-file-identical` | reject | ❌ other | ❌ other | ❌ other | ❌ other | ❌ other | nothing | [why](#s09-tree-duplicate-file-identical) |
| [S10](https://stoppels.ch/tar/S10.html) `tree-symlink-then-file` | reject | ❌ other | ❌ other | ❌ other | ❌ other | ❌ other | nothing | [why](#s10-tree-symlink-then-file) |
| [S11](https://stoppels.ch/tar/S11.html) `tree-through-symlink` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | nothing |  |
| [S12](https://stoppels.ch/tar/S12.html) `tree-under-file` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | nothing |  |
| [S13](https://stoppels.ch/tar/S13.html) `hardlink-empty-target` | reject | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | ✅ rejected | `symlink_target_unavailable` |  |
