# archivey newcomer review

## Environment

Tested on November 8, 2026: Debian GNU/Linux 13.6, x86-64, Linux 6.18.57, CPython 3.12.14.

Three separate virtual environments:

| Environment | Packages used |
| --- | --- |
| Core | archivey 0.3.0 |
| Recommended | archivey 0.3.0, archivey-cli 0.3.0 |
| Alternatives | libarchive-c 5.3 with libarchive 3.7.4; py7zr 1.1.4; pyzipper 0.4.0; Python’s zipfile, tarfile and gzip |
| Fixture generation | py7zr 1.1.4, pyzipper 0.4.0, pycdlib 1.22.0 |

rarfile 4.5 was installed but not exercised. No RAR fixtures were created. RAR, split archives, Windows/macOS behavior and the additional claimed container formats remain unverified.

I read the live [documentation home page](https://archivey-dev.github.io/archivey/) before the first-use test, then relevant sections of [llms-full.txt](https://archivey-dev.github.io/archivey/llms-full.txt). I did not consult repository sources, issues, pull requests or design notes. **I never read the installed package’s source code.**

## Verdict

I would adopt archivey for an application that genuinely needs several archive formats. The uniform API worked across ZIP, compressed TAR, 7z and ISO; the malicious fixtures did not escape extraction; streaming memory stayed small; and encryption errors were useful. For a ZIP/TAR-only application, the dependency is harder to justify: the standard library was equally concise for ordinary reads and slightly faster in this benchmark. Adoption would require explicitly handling extraction reports, keeping application-level read limits, and wrapping archive verification carefully. Its experimental verification API is a particular dependency risk. These tests found one clear documentation contradiction, but no demonstrated extraction vulnerability or ordinary read failure.

**Adopt with caveats.**

## Task results

Everything in this table was **run**. Line counts are nonblank physical lines inside the relevant function or benchmark branch, excluding imports, function declarations and test harnesses. They measure the compact implementations below, including their semicolons—not an inherent measure of API quality.

| task | archivey lines | alternative used | alternative lines | worked? | notes |
| --- | ---: | --- | ---: | --- | --- |
| First-use ZIP listing and extraction | 4 | — | — | Yes | Home-page examples worked immediately. |
| First-use tar.gz listing and extraction | 4 | — | — | Yes | Same API; no format-specific adjustment. |
| a. Unknown-format metadata listing | 2 | libarchive-c | 2 | Yes | Tested ZIP, tar.gz, 7z, ISO and ZIP renamed `.bin`. ISO naming differs. |
| b. Bounded extraction rejecting unsafe members | 2 | libarchive-c plus manual policy | 17 | Yes | Alternative rejects all links; archivey supports a richer policy. Both require a destination protected from hostile concurrent modification. |
| c. Read one member | 1 | zipfile / tarfile | 1 / 2 | Yes | Same returned bytes. TAR can still require preceding decompression. |
| d. Stream and hash 1.0625 GiB | 6 | tarfile / libarchive-c | 7 / 6 | Yes | All 17 hashes matched independently generated expectations. |
| e. AES ZIP, correct/wrong password | 1 | pyzipper | 1 | Yes | Both rejected the wrong password. |
| e. Header-encrypted 7z, correct/wrong password | 1 | py7zr | 2 | Yes | Archivey read directly; the tested py7zr alternative extracted the selected member. |
| f. Verify damaged/truncated ZIP | 4 | zipfile | 3 | Yes | Archivey needs both member failures and listing error checked. |
| f. Verify truncated/corrupt tar.gz | 4 | gzip plus tarfile | 7 | Yes | Alternative explicitly drains gzip after TAR processing to check its trailer. |
| g. CLI list/extract ZIP and tar.gz | 4 commands | Python zipfile/tarfile CLIs | 4 commands | Yes | Archivey uses one command vocabulary for both formats. |

## Findings

### F1: Installation is straightforward, but “recommended” still has boundaries

- Kind: install
- Severity: minor
- Evidence: ran it; RAR’s external-tool requirement is docs only.
- What I did: created independent virtualenvs and ran:
  ```bash
  pip install archivey
  pip install "archivey[recommended]"
  pip install archivey-cli
  ```
- What happened:

  | Installation | Elapsed | Result |
  | --- | ---: | --- |
  | Core, fresh environment | 18.153 s | archivey 0.3.0 only |
  | Recommended, separate fresh environment | 13.607 s | archivey plus ten dependencies |
  | archivey-cli, into recommended environment | 15.460 s | Added archivey-cli 0.3.0 |

  The second installation reused the cached archivey wheel, so its shorter time is not evidence that the extra is cheaper.

  Recommended installed:

  ```text
  backports-zstd 1.8.0
  brotli 1.2.1
  cryptography 50.0.2
  inflate64 1.0.4
  lz4 4.4.5
  pycdlib 1.22.0
  pyppmd 1.3.1
  tqdm 4.70.1
  cffi 2.1.1
  pycparser 3.12
  ```

  There were no installation failures or package-specific warnings. Some later pip invocations printed the ordinary pip-update notice.

  Core-only ISO opening failed with this actionable exception:

  ```text
  PackageNotInstalledError: Format ISO is not available: missing pycdlib (pip install archivey[recommended]) (format=ISO)
  ```

  Core-only encrypted reads failed with:

  ```text
  PackageNotInstalledError: The 'cryptography' package is required for WinZip AES decryption (pip install archivey[recommended]). (archive='fixtures/secret.zip', member='hello.txt', format=ZIP)
  ```

  ```text
  PackageNotInstalledError: The 'cryptography' package is required for AES decryption (pip install archivey[recommended]).
  ```

- What I expected, and why: the home page clearly maps core versus recommended for the tested formats. It also explicitly says compressed RAR requires an external program. That part is clear documentation, but an operational dependency I did not validate. The CLI already existed in the core package; installing archivey-cli was unnecessary for this environment, though it worked as requested.

### F2: Safe extraction does not mean every rejected member raises

- Kind: API friction
- Severity: major
- Evidence: ran it.
- What I did: extracted self-created ZIP/TAR archives containing traversal paths, an absolute path, escaping symlinks, a symlink followed by a child entry, a hardlink to a missing outside target, a FIFO and a character device:
  ```python
  with archivey.open_archive(path) as a:
      report = a.extract_all(destination)
  ```
- What happened: ordinary unsafe entries were skipped, safe entries before and after them were extracted, and the call returned normally. Representative exact report error messages:

  ```text
  Path traversal ('..') in member name (member='../ESCAPE')
  Absolute path not allowed (member='/workspace/scratch/1d5d052b5c47/fixtures/ABSOLUTE_ESCAPE')
  Symlink target escapes destination (member='link', target='../../ESCAPE')
  Symlink target escapes destination (member='pivot', target='../../')
  Special file (device/FIFO/socket) not allowed (member='pipe')
  Special file (device/FIFO/socket) not allowed (member='device')
  ```

  The results had status `blocked`. Neither outside sentinel existed afterward:

  ```text
  ESCAPES [('ESCAPE', False), ('fixtures/ABSOLUTE_ESCAPE', False)]
  ```

  The symlink-pivot fixture produced a regular directory containing `pivot/ESCAPE` inside the destination. It did not create the escaping symlink.

  The missing hardlink target followed a different error path:

  ```text
  LinkTargetNotFoundError: Hardlink target not found (member='link', target='../../ESCAPE')
  ```

  Asking extraction to stop on blocked members worked:

  ```python
  a.extract_all(destination, abort_on=["blocked_member"])
  ```

  ```text
  FilterRejectionError: Path traversal ('..') in member name (member='../ESCAPE')
  ```

  The CLI made the distinction visible: traversal extraction exited **3**, with:

  ```text
  blocked: ../ESCAPE: Path traversal ('..') in member name (member='../ESCAPE')
  2 extracted, 0 renamed, 0 skipped, 1 blocked → cli-out-evil/
  ```

- What I expected, and why: a security-conscious caller can easily interpret “returned without exception” as complete success. The detailed docs explain the behavior correctly, but the home-page extraction example discards the report. Production code should inspect it or explicitly use `abort_on`. The protections passed these tests; this finding concerns integration semantics.

### F3: Bomb and extraction limits worked, with useful errors

- Kind: security
- Severity: minor
- Evidence: ran it.
- What I did: created a ZIP containing 32 MiB of zeros, compressed into 32,617 bytes: **1028.74:1**. I also tried a five-byte extraction allowance and a one-entry allowance.
  ```python
  a.extract_all(out)
  a.extract_all(out, limits=archivey.ExtractionLimits(max_extracted_bytes=5))
  a.extract_all(out, limits=archivey.ExtractionLimits(max_entries=1))
  ```
- What happened:

  ```text
  ResourceLimitError: Decompression ratio 1029:1 exceeds limit max_ratio=800:1 (from recorded sizes: 33554432 bytes from 32617 compressed) (member='zeros')
  ```

  Reading the bomb also stopped:

  ```text
  ResourceLimitError: Decompression ratio 804:1 exceeds limit max_ratio=800:1 (archive='fixtures/bomb.zip', member='zeros', format=ZIP)
  ```

  The smaller extraction allowances failed with:

  ```text
  AlwaysStopResourceLimitError: Extraction limit reached: max_extracted_bytes=5 (written 0 bytes; the next 6-byte chunk would make 6)
  ```

  ```text
  AlwaysStopResourceLimitError: Entry-count limit reached: max_entries=1 (would write entry 2)
  ```

  The manual libarchive alternative rejected the bomb with my own:

  ```text
  ValueError: output byte limit exceeded
  ```

- What I expected, and why: these protections should apply before an archive consumes uncontrolled output space. They did for the tested fixtures. The messages identify the limit and offending member. This is positive security evidence, not proof against all archive-bomb constructions.

### F4: Extraction byte limits do not protect application reads

- Kind: API friction
- Severity: major
- Evidence: ran it.
- What I did: configured a 1,024-byte extraction allowance, then read an 8 MiB incompressible ZIP member:
  ```python
  cfg = archivey.ArchiveyConfig(
      extraction_limits=archivey.ExtractionLimits(max_extracted_bytes=1024)
  )
  with archivey.open_archive("fixtures/read-cap.zip", config=cfg) as a:
      print(len(a.read("data")))
  ```
- What happened:
  ```text
  read bytes with 1024-byte extraction cap: 8388608
  ```
- What I expected, and why: the behavior matches the detailed docs and the setting’s name. Nevertheless, the safe-extraction promise does not provide a general byte budget for an upload scanner that calls `read()`. The ratio guard cannot substitute for an absolute cap on incompressible data. Applications reading untrusted members need their own byte counter and bounded reads.

### F5: An empty verification failure list can conceal a truncated archive

- Kind: API friction
- Severity: major
- Evidence: ran it; experimental API status is docs only.
- What I did: cut a generated ZIP in half, then called:
  ```python
  failures = a.verify_all()
  listing_error = a.members_report().error
  ```
- What happened: `failures` was **empty**, while the listing report contained:

  ```text
  TruncatedError: ZIP stream ends inside the central directory, before the end of central directory record (archive='fixtures/truncated.zip', format=ZIP)
  ```

  Reading the intact first member still succeeded:

  ```text
  b'hello\n'
  ```

  A complete listing raised the truncation error. The CLI test exited 1 and printed:

  ```text
  FAIL: ZIP stream ends inside the central directory, before the end of central directory record (archive='fixtures/truncated.zip', format=ZIP)
  2 OK, 1 failed
  ```

  Other integrity failures were detected:

  ```text
  CorruptionError: Digest mismatch for 'crc32': stored value does not match the decompressed content. (archive='fixtures/crc.zip', member='hello.txt', format=ZIP)
  ```

  ```text
  TruncatedError: gzip stream is truncated (archive='fixtures/truncated.tar.gz', member='truncated.tar', format=GZ)
  ```

  Corrupting the gzip trailer produced an internal-looking subclass name:

  ```text
  _StreamChecksumError: Error reading gzip stream: Error -3 while decompressing data: incorrect data check (archive='fixtures/bad-trailer.tar.gz', format=TAR_GZ)
  ```

  I checked at runtime that this last exception **is a `CorruptionError`**.

  The alternative verification code produced:

  ```text
  ValueError: CRC failure: hello.txt
  BadZipFile: File is not a zip file
  EOFError: Compressed file ended before the end-of-stream marker was reached
  BadGzipFile: CRC check failed 0x275e0d7d != 0x275e0d7c
  ```

  An earlier tarfile-only streaming attempt reported `ReadError: truncated header`; the final alternative also drains the outer gzip stream.

- What I expected, and why: a method named `verify_all()` invites a single success/failure interpretation. Instead, callers must combine member failures, listing errors and potentially diagnostics. The docs explicitly explain this, so it is not an undocumented implementation bug. They also mark `verify_all()` and the verification state API as experimental, allowing changes even in patch releases. I would isolate this behind an application-owned wrapper.

### F6: Truncation can change the detected container and its member names

- Kind: error message
- Severity: minor
- Evidence: ran it.
- What I did: cut the small generated tar.gz in half, then listed it and tried the original TAR member name.
  ```python
  with archivey.open_archive("fixtures/truncated.tar.gz") as a:
      print([(m.name, m.size) for m in a])
      a.read("hello.txt")
  ```
- What happened: listing succeeded as a single gzip member:

  ```text
  [('truncated.tar', None)]
  ```

  Reading the expected TAR member failed with:

  ```text
  KeyError: "Member 'hello.txt' not found"
  ```

  Verification subsequently reported gzip truncation, as quoted in F5.

  An unrelated invalid file produced this exact, actionable but lengthy message:

  ```text
  FormatDetectionError: Could not detect archive format: no magic bytes or file extension matched. A raw LZMA Alone, zlib or Brotli stream has no magic and is only recognised by its extension: give the file one (.lzma, .zz, .br), pass format=, use open_stream(), or set ArchiveyConfig(always_probe_content=True). No ZIP, 7z or RAR archive starts in the first 2097152 bytes behind other data either; for one further in, pass format=. (archive='fixtures/not-archive.bin')
  ```

- What I expected, and why: damaged input can reasonably prevent recognition of the inner TAR. However, a successful list followed by a missing-member error is a misleading first symptom. Listing is not an integrity check, and callers should preserve that distinction in their own error reporting.

### F7: Unified timestamps still require normalization

- Kind: API friction
- Severity: minor
- Evidence: ran it.
- What I did: compared `modified` from a ZIP member with `modified` from a TAR member.
  ```python
  zip_member.modified < tar_member.modified
  ```
- What happened:
  ```text
  TypeError: can't compare offset-naive and offset-aware datetimes
  ```

  ZIP supplied a naive datetime; TAR supplied a UTC-aware datetime. Using the documented helpers worked:

  ```python
  zip_member.modified_utc() < tar_member.modified_utc()
  ```

- What I expected, and why: the library faithfully preserves formats’ timestamp semantics, which is defensible and documented. A newcomer expecting uniform metadata to be directly sortable can still trip over it. The correct normalization helper already exists.

### F8: Password handling was good; the alternatives were not consistently clearer

- Kind: error message
- Severity: minor
- Evidence: ran it.
- What I did: generated an AES ZIP and a header-encrypted 7z using password `correct`; tried no password, `wrong`, and `correct`.
  ```python
  with archivey.open_archive(path, password=password) as a:
      a.read("hello.txt")
  ```
- What happened: correct passwords returned `b'hello\n'`. Other attempts produced:

  ```text
  EncryptionError: Password required to read this encrypted member (archive='fixtures/secret.zip', member='hello.txt', format=ZIP)
  ```

  ```text
  EncryptionError: Wrong password for this ZIP member (archive='fixtures/secret.zip', member='hello.txt', format=ZIP)
  ```

  ```text
  EncryptionError: Password required to decrypt the 7z header
  ```

  ```text
  EncryptionError: Password(s) rejected for the 7z header
  ```

  pyzipper’s wrong-password result was understandable:

  ```text
  RuntimeError: Bad password for file 'hello.txt'
  ```

  py7zr’s was not:

  ```text
  TypeError: Unknown field: b'\xfb'
  ```

- What I expected, and why: wrong passwords should produce an identifiable authentication/decryption error. Archivey did that consistently in these tests. Its messages were actionable without inspecting implementation details.

### F9: CLI dry-run documentation contradicts observed destination checking

- Kind: docs wrong
- Severity: minor
- Evidence: ran it.
- What I did: ran the same dry-run against an absent directory and a directory already containing `hello.txt`.
  ```bash
  archivey extract fixtures/basic.zip -d dry-empty --dry-run --overwrite error
  archivey extract fixtures/basic.zip -d dry-existing --dry-run --overwrite error
  ```
- What happened: the empty destination exited 0; the existing destination exited 1:

  ```text
  failed: hello.txt: Destination already exists: dry-existing/hello.txt (member='hello.txt')
  peak use of the reader limits: listing 3 members, 54 metadata bytes
  dry run, nothing written: 2 extracted, 0 renamed, 0 skipped, 1 failed → dry-existing/
  ```

  The existing file remained `b'existing'`.

- What I expected, and why: the CLI section says dry-run has the same report and exit status as extraction into an empty folder. That is false for this test. The extraction guide elsewhere correctly explains that existing destination contents are considered. The behavior is useful; the CLI description needs correction.

### F10: Streaming is memory-efficient, with measurable overhead here

- Kind: performance
- Severity: minor
- Evidence: ran it.
- What I did: generated 17 files of 64 MiB each using reproducible pseudorandom bytes, compressed them into a tar.gz, and hashed every file using chunked reads. Expected hashes were computed during generation. Each implementation ran in three separate processes, with order varied.
- What happened:

  Payload: **1,140,850,688 bytes**. Compressed archive: **1,141,199,641 bytes**.

  | Implementation | Median elapsed | Range | Maximum peak RSS |
  | --- | ---: | ---: | ---: |
  | archivey | 1.629 s | 1.620–1.641 s | 34.10 MiB |
  | tarfile | 1.544 s | 1.533–1.563 s | 14.05 MiB |
  | libarchive-c | 1.071 s | 1.034–1.077 s | 13.63 MiB |

  Every run hashed all 17 files correctly. Archivey was about 6% slower than tarfile and 52% slower than libarchive-c by median elapsed time.

- What I expected, and why: streaming should avoid memory proportional to the uncompressed archive, and it did. These are short, mostly cached, low-compression TAR measurements—not a general performance ranking or evidence about solid 7z performance. The extra memory is modest in absolute terms but relevant in small workers.

### F11: A documented compatibility path already produces a deprecation warning

- Kind: API friction
- Severity: nit
- Evidence: ran it.
- What I did:
  ```python
  archivey.ExtractionLimits(max_ratio=800.0)
  ```
- What happened: construction worked, with:

  ```text
  DeprecationWarning: The ratio fields of ExtractionLimits (max_ratio, ratio_activation_threshold, live_ratio_activation_threshold) are deprecated and will be removed in a future release; set them on DecoderLimits, which holds reads and listing as well as extraction.
  ```

- What I expected, and why: the reference correctly labels these arguments deprecated. New code should use `DecoderLimits`; copying constructor representations or older examples can introduce an avoidable migration.

## Where archivey is better than the alternatives

- **Tasks a/c/e:** one opening and reading API worked across ZIP, tar.gz, 7z and ISO, including a misleading filename.
- **Task b:** useful extraction policy, reports, bomb guards and output limits required substantially less application code than the tested libarchive approach.
- **Task d:** the home page directly teaches archive-order streaming, and the tested implementation handled over 1 GiB with modest memory.
- **Task e:** consistent, meaningful password exceptions across AES ZIP and encrypted 7z.
- **Tasks f/g:** the CLI detected member damage and incomplete listings and returned failure exit statuses without custom verification code.

## Where the alternatives are better

- **Tasks c/e:** zipfile and pyzipper were equally concise for their specific formats, reducing the value of an extra abstraction in a narrowly scoped application.
- **Task d:** tarfile used less than half the peak RSS and was slightly faster here; libarchive-c was faster still.
- **Task a:** libarchive-c already provides a comparably short unknown-format listing API. Archivey is not uniquely capable of format unification.
- **Task f:** direct format-specific code can make the scope of verification explicit. Archivey’s multiple reporting channels and experimental verification API need a wrapper.
- **First-use ZIP/TAR tasks:** the standard-library alternatives require no additional package installation.

## Scripts


Save the following files together and run `bash rerun.sh` in a fresh working directory. It installs whatever PyPI currently serves; the versions above identify this review’s run. Fixture timestamps, encrypted-header bytes, paths and timings will vary.

`rerun.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
python -m venv base
TIMEFORMAT='%R seconds'
{ time base/bin/pip install archivey; } > install-base.log 2>&1
curl -L --fail https://archivey-dev.github.io/archivey/ -o home.html
python - <<'PY'
from html.parser import HTMLParser
class P(HTMLParser):
 def handle_data(self,d):
  if d.strip(): print(d.strip())
P().feed(open('home.html').read())
PY
base/bin/python first.py
python -m venv recommended
{ time recommended/bin/pip install 'archivey[recommended]'; } > install-recommended.log 2>&1
curl -L --fail https://archivey-dev.github.io/archivey/llms-full.txt -o docs.txt
python -m venv alternatives
alternatives/bin/pip install libarchive-c py7zr pyzipper rarfile pycdlib > install-alternatives.log 2>&1
{ time recommended/bin/pip install archivey-cli; } > install-cli.log 2>&1
alternatives/bin/python fixtures.py > fixtures.log 2>&1
recommended/bin/python probe.py > probe.log 2>&1
base/bin/python probe.py > probe-base.log 2>&1
recommended/bin/python tasks.py > tasks.log 2>&1
alternatives/bin/python alternatives.py > alternatives.log 2>&1
alternatives/bin/python cli.py > cli.log 2>&1
recommended/bin/python edge.py > edge.log 2>&1
for mode in archivey tarfile libarchive libarchive tarfile archivey tarfile archivey libarchive; do
 if [ "$mode" = archivey ]; then
  recommended/bin/python bench.py "$mode"
 else
  alternatives/bin/python bench.py "$mode"
 fi
done > bench-all.log
recommended/bin/archivey --version -v > capabilities.log
recommended/bin/pip list --format=freeze > versions-recommended.txt
alternatives/bin/pip list --format=freeze > versions-alternatives.txt
```

`first.py`:

```python
import io, tarfile, zipfile
from pathlib import Path
import archivey
Path('fixtures').mkdir(exist_ok=True)
with zipfile.ZipFile('fixtures/basic.zip','w') as z:
 z.writestr('hello.txt', b'hello\n')
with tarfile.open('fixtures/basic.tar.gz','w:gz') as t:
 m=tarfile.TarInfo('hello.txt'); m.size=6; m.mtime=1700000000
 t.addfile(m,io.BytesIO(b'hello\n'))
for p in ('fixtures/basic.zip','fixtures/basic.tar.gz'):
 with archivey.open_archive(p) as a:
  for m in a: print(p,m.name,m.size)
  a.extract_all(p+'.out')
 print(Path(p+'.out/hello.txt').read_bytes())
```

`fixtures.py`:

```python
import io, os, stat, tarfile, zipfile, shutil, gzip, random, json, hashlib
from pathlib import Path
import py7zr, pyzipper, pycdlib
p=Path('fixtures'); p.mkdir(exist_ok=True)
with zipfile.ZipFile(p/'basic.zip','w',compression=zipfile.ZIP_DEFLATED) as z:
 z.writestr('hello.txt',b'hello\n'); z.writestr('dir/',b''); z.writestr('dir/second.txt',b'second\n')
with tarfile.open(p/'basic.tar.gz','w:gz') as t:
 for name,data in [('hello.txt',b'hello\n'),('dir/second.txt',b'second\n')]:
  m=tarfile.TarInfo(name); m.size=len(data); m.mtime=1700000000; t.addfile(m,io.BytesIO(data))
shutil.copy(p/'basic.zip',p/'unknown.bin')
absolute=str((p/'ABSOLUTE_ESCAPE').resolve())
for fmt in ('zip','tar'):
 for case,name,target,kind in [('traversal','../ESCAPE','', 'file'),('absolute',absolute,'','file'),('symlink','link','../../ESCAPE','symlink'),('hardlink','link','../../ESCAPE','hardlink'),('fifo','pipe','','fifo'),('device','device','','device'),('pivot','pivot','../../','symlink')]:
  if fmt=='zip' and kind in ('hardlink','fifo','device'): continue
  path=p/f'{case}.{fmt}'
  if fmt=='zip':
   with zipfile.ZipFile(path,'w') as z:
    z.writestr('before',b'ok')
    m=zipfile.ZipInfo(name); m.create_system=3
    m.external_attr=((stat.S_IFLNK|0o777) if kind=='symlink' else (stat.S_IFREG|0o644))<<16
    z.writestr(m,target.encode() if kind=='symlink' else b'evil')
    if case=='pivot': z.writestr('pivot/ESCAPE',b'evil')
    z.writestr('after',b'ok')
  else:
   with tarfile.open(path,'w') as t:
    for n,d,k,ln in [('before',b'ok','file',''),(name,b'evil',kind,target)]+([('pivot/ESCAPE',b'evil','file','')] if case=='pivot' else [])+[('after',b'ok','file','')]:
     m=tarfile.TarInfo(n); m.type={'file':tarfile.REGTYPE,'symlink':tarfile.SYMTYPE,'hardlink':tarfile.LNKTYPE,'fifo':tarfile.FIFOTYPE,'device':tarfile.CHRTYPE}[k]; m.linkname=ln; m.size=len(d) if k=='file' else 0
     t.addfile(m,io.BytesIO(d) if k=='file' else None)
with zipfile.ZipFile(p/'bomb.zip','w',compression=zipfile.ZIP_DEFLATED) as z: z.writestr('zeros',b'\0'*(32*2**20))
with zipfile.ZipFile(p/'crc.zip','w') as z: z.writestr('hello.txt',b'hello\n')
b=bytearray((p/'crc.zip').read_bytes()); b[b.index(b'hello\n')]=ord('X'); (p/'crc.zip').write_bytes(b)
for src in ('basic.zip','basic.tar.gz'):
 b=(p/src).read_bytes(); (p/('truncated.'+src.split('.',1)[1])).write_bytes(b[:len(b)//2])
(p/'not-archive.bin').write_bytes(b'not an archive\n')
with pyzipper.AESZipFile(p/'secret.zip','w',encryption=pyzipper.WZ_AES) as z:
 z.setpassword(b'correct'); z.writestr('hello.txt',b'hello\n')
with py7zr.SevenZipFile(p/'secret.7z','w',password='correct',header_encryption=True) as z: z.writestr(b'hello\n','hello.txt')
with py7zr.SevenZipFile(p/'basic.7z','w') as z: z.writestr(b'hello\n','hello.txt')
iso=pycdlib.PyCdlib(); iso.new(); iso.add_fp(io.BytesIO(b'hello\n'),6,'/HELLO.TXT;1'); iso.write(str(p/'basic.iso')); iso.close()
# 1.0625 GiB of reproducible incompressible input, never held as one allocation.
rng=random.Random(12345); hashes={}
with tarfile.open(p/'large.tar.gz','w:gz',compresslevel=1) as t:
 for i in range(17):
  data=rng.randbytes(64*2**20); name=f'{i:02}.bin'; hashes[name]=hashlib.sha256(data).hexdigest()
  m=tarfile.TarInfo(name); m.size=len(data); t.addfile(m,io.BytesIO(data))
(p/'hashes.json').write_text(json.dumps(hashes,sort_keys=True))
print('large payload',17*64*2**20,'compressed',(p/'large.tar.gz').stat().st_size)
with zipfile.ZipFile(p/'bomb.zip') as z:
 m=z.infolist()[0]; print('bomb',m.file_size,m.compress_size,m.file_size/m.compress_size)
```

`probe.py`:

```python
import archivey, json, shutil, sys
from pathlib import Path
p=Path('fixtures'); root=Path('outputs')
def run(label,fn):
 try: print(label,'OK',fn())
 except Exception as e: print(label,'ERROR',type(e).__name__,str(e))
def listing(path):
 with archivey.open_archive(path) as a:
  return [(m.name,m.size,m.type.value,str(m.modified)) for m in a]
def read(path,password=None,name='hello.txt'):
 with archivey.open_archive(path,password=password) as a: return a.read(name)
def extract(path,**kw):
 out=root/(path.name+str(len(list(root.glob('*'))))); out.mkdir(parents=True,exist_ok=True)
 with archivey.open_archive(path) as a:
  report=a.extract_all(out,**kw)
  return [(r.member.name,r.status.value,str(r.error)) for r in report],sorted(str(f.relative_to(out)) for f in out.rglob('*'))
for name in ['basic.zip','basic.tar.gz','unknown.bin','basic.7z','basic.iso']:
 run('LIST '+name,lambda name=name:listing(p/name))
 run('READ '+name,lambda name=name:read(p/name,name='/HELLO.TXT;1' if name.endswith('iso') else 'hello.txt'))
for name in ['traversal.zip','absolute.zip','symlink.zip','pivot.zip','traversal.tar','absolute.tar','symlink.tar','hardlink.tar','fifo.tar','device.tar','pivot.tar','bomb.zip']:
 run('EXTRACT '+name,lambda name=name:extract(p/name))
run('ABORT traversal.zip',lambda:extract(p/'traversal.zip',abort_on=['blocked_member']))
run('LIMIT basic.zip',lambda:extract(p/'basic.zip',limits=archivey.ExtractionLimits(max_extracted_bytes=5)))
run('LIMIT entries',lambda:extract(p/'basic.zip',limits=archivey.ExtractionLimits(max_entries=1)))
for name in ['secret.zip','secret.7z']:
 for password in [None,'wrong','correct']:
  run('PASSWORD '+name+' '+str(password),lambda name=name,password=password:read(p/name,password))
for name in ['crc.zip','truncated.zip','truncated.tar.gz','not-archive.bin']:
 run('BROKEN list '+name,lambda name=name:listing(p/name))
 run('BROKEN read '+name,lambda name=name:read(p/name))
 def verify(name=name):
  with archivey.open_archive(p/name) as a:
   failures=a.verify_all(); report=a.members_report()
   return [(m.name,type(e).__name__,str(e)) for m,e in failures], (type(report.error).__name__,str(report.error)) if report.error else None, str(a.diagnostics.counts)
 run('VERIFY '+name,verify)
run('BOMB read',lambda:read(p/'bomb.zip',name='zeros'))
run('DOCUMENTED ExtractionLimits max_ratio',lambda:archivey.ExtractionLimits(max_ratio=800.0))
print('ESCAPES',[(str(x),x.exists()) for x in [Path('ESCAPE'),p/'ABSOLUTE_ESCAPE']])
```

The ISO read in that exploratory script intentionally preserves my initial wrong guess. It produced:

```text
KeyError: "Member '/HELLO.TXT;1' not found"
```

Listing showed `HELLO.TXT`; using that name succeeded in `tasks.py`. This was my incorrect assumption, not an archivey bug.

`tasks.py`:

```python
import archivey, hashlib, json, shutil, io, tarfile, zipfile
from pathlib import Path

def listing(p):
 with archivey.open_archive(p) as a:
  return [(m.name,m.size,m.type,m.modified) for m in a]
def extract(p,dest):
 with archivey.open_archive(p) as a:
  return a.extract_all(dest,abort_on=['blocked_member'],limits=archivey.ExtractionLimits(max_extracted_bytes=16*2**20))
def read(p,name='hello.txt',password=None):
 with archivey.open_archive(p,password=password) as a: return a.read(name)
def verify(p):
 with archivey.open_archive(p,config=archivey.ArchiveyConfig(diagnostic_policy=archivey.DiagnosticPolicy.STRICT)) as a:
  failures=a.verify_all()
  if failures: raise failures[0][1]
  if error:=a.members_report().error: raise error

def run(label,fn):
 try: print(label,'OK',fn())
 except Exception as e: print(label,'ERROR',type(e).__name__,str(e))
if __name__=='__main__':
 for name in ['basic.zip','basic.tar.gz','unknown.bin','basic.7z','basic.iso']:
  run('list '+name,lambda name=name:listing('fixtures/'+name))
  run('read '+name,lambda name=name:read('fixtures/'+name,'HELLO.TXT' if name.endswith('iso') else 'hello.txt'))
 for name in ['basic.zip','basic.tar.gz']:
  dest='tasks-out-'+name; shutil.rmtree(dest,ignore_errors=True)
  run('extract '+name,lambda name=name,dest=dest:len(extract('fixtures/'+name,dest)))
 # A valid tar's content with a corrupt gzip trailer.
 p=Path('fixtures/bad-trailer.tar.gz'); b=bytearray(Path('fixtures/basic.tar.gz').read_bytes()); b[-8]^=1; p.write_bytes(b)
 for name in ['crc.zip','truncated.zip','truncated.tar.gz','bad-trailer.tar.gz','basic.zip','basic.tar.gz']:
  run('verify '+name,lambda name=name:verify('fixtures/'+name))
 with archivey.open_archive('fixtures/basic.zip') as z, archivey.open_archive('fixtures/basic.tar.gz') as t:
  a=z.get('hello.txt'); b=t.get('hello.txt')
  run('compare raw modified',lambda:a.modified<b.modified)
  print('compare modified_utc',a.modified_utc()<b.modified_utc())
 print('escapes',Path('ESCAPE').exists(),Path('fixtures/ABSOLUTE_ESCAPE').exists())
```

`alternatives.py`:

```python
import datetime, hashlib, shutil, tarfile, zipfile, os, gzip
from pathlib import Path, PurePosixPath, PureWindowsPath
import libarchive, py7zr, pyzipper

def listing(p):
 with libarchive.file_reader(str(p)) as a:
  return [(m.pathname,m.size,m.filetype,m.mtime) for m in a]

def extract(p,dest,cap=16*2**20):
 # Caller supplies a newly created private destination, free of existing symlinks.
 dest=Path(dest); dest.mkdir(mode=0o700,parents=True,exist_ok=False); used=0
 with libarchive.file_reader(str(p)) as a:
  for m in a:
   n=PurePosixPath(m.pathname)
   if n.is_absolute() or '..' in n.parts or '\\' in m.pathname or PureWindowsPath(m.pathname).drive:
    raise ValueError('unsafe name: '+m.pathname)
   if not (m.isfile or m.isdir) or m.issym or m.islnk:
    raise ValueError('refused member type: '+m.pathname)
   out=dest.joinpath(*n.parts)
   if m.isdir: out.mkdir(parents=True,exist_ok=True); continue
   out.parent.mkdir(parents=True,exist_ok=True)
   with out.open('xb') as f:
    for b in m.get_blocks():
     used+=len(b)
     if used>cap: raise ValueError('output byte limit exceeded')
     f.write(b)
 return used

def read_zip(p):
 with zipfile.ZipFile(p) as a: return a.read('hello.txt')
def read_tar(p):
 with tarfile.open(p) as a:
  with a.extractfile('hello.txt') as s: return s.read()
def encrypted_zip(p,password):
 with pyzipper.AESZipFile(p) as a: return a.read('hello.txt',pwd=password.encode())
def encrypted_7z(p,password,dest):
 with py7zr.SevenZipFile(p,password=password) as a: a.extract(path=dest,targets=['hello.txt'])
 return (Path(dest)/'hello.txt').read_bytes()
def verify_zip(p):
 with zipfile.ZipFile(p) as a:
  bad=a.testzip()
  if bad: raise ValueError('CRC failure: '+bad)
def verify_tar(p):
 with gzip.open(p) as outer:
  with tarfile.open(fileobj=outer,mode='r|') as a:
   for m in a:
    if m.isfile():
     with a.extractfile(m) as s:
      while s.read(2**20): pass
  while outer.read(2**20): pass

def run(label,fn):
 try: print(label,'OK',fn())
 except Exception as e: print(label,'ERROR',type(e).__name__,str(e))
if __name__=='__main__':
 for name in ['basic.zip','basic.tar.gz','unknown.bin','basic.7z','basic.iso']:
  run('LIST '+name,lambda name=name:listing('fixtures/'+name))
 run('READ zip',lambda:read_zip('fixtures/basic.zip'))
 run('READ tar',lambda:read_tar('fixtures/basic.tar.gz'))
 for i,name in enumerate(['basic.zip','basic.tar.gz','traversal.zip','absolute.zip','symlink.zip','pivot.zip','traversal.tar','absolute.tar','symlink.tar','hardlink.tar','fifo.tar','device.tar','pivot.tar','bomb.zip']):
  dest='alt-outputs/'+str(i); shutil.rmtree(dest,ignore_errors=True)
  run('EXTRACT '+name,lambda name=name,dest=dest:extract('fixtures/'+name,dest))
 for pw in ['wrong','correct']:
  run('AES ZIP '+pw,lambda pw=pw:encrypted_zip('fixtures/secret.zip',pw))
  run('7z '+pw,lambda pw=pw:encrypted_7z('fixtures/secret.7z',pw,'alt-secret-'+pw))
 for name in ['crc.zip','truncated.zip']:
  run('VERIFY '+name,lambda name=name:verify_zip('fixtures/'+name))
 for name in ['truncated.tar.gz','bad-trailer.tar.gz']:
  run('VERIFY '+name,lambda name=name:verify_tar('fixtures/'+name))
```

The alternative extractor is deliberately restrictive and leaves earlier output, including a partial current file, when it raises. Its exact rejection messages were:

```text
ValueError: unsafe name: ../ESCAPE
ValueError: unsafe name: /workspace/scratch/1d5d052b5c47/fixtures/ABSOLUTE_ESCAPE
ValueError: refused member type: link
ValueError: refused member type: pivot
ValueError: refused member type: pipe
ValueError: refused member type: device
```

`bench.py`:

```python
import hashlib, json, resource, sys, time
from pathlib import Path
mode=sys.argv[1]; start=time.perf_counter(); result={}; count=0
if mode=='archivey':
 import archivey
 with archivey.open_archive('fixtures/large.tar.gz',streaming=True) as a:
  for m,s in a.stream_members():
   if not m.is_file or s is None: continue
   h=hashlib.sha256()
   while b:=s.read(2**20): h.update(b); count+=len(b)
   result[m.name]=h.hexdigest()
elif mode=='tarfile':
 import tarfile
 with tarfile.open('fixtures/large.tar.gz','r|gz') as a:
  for m in a:
   if not m.isfile(): continue
   h=hashlib.sha256()
   with a.extractfile(m) as s:
    while b:=s.read(2**20): h.update(b); count+=len(b)
   result[m.name]=h.hexdigest()
else:
 import libarchive
 with libarchive.file_reader('fixtures/large.tar.gz') as a:
  for m in a:
   if not m.isfile: continue
   h=hashlib.sha256()
   for b in m.get_blocks(): h.update(b); count+=len(b)
   result[m.pathname]=h.hexdigest()
assert result==json.loads(Path('fixtures/hashes.json').read_text())
print(json.dumps(dict(mode=mode,seconds=round(time.perf_counter()-start,3),max_rss_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,bytes=count,files=len(result),hashes_match=True)))
```

`cli.py`:

```python
import subprocess, sys, shutil
from pathlib import Path
exe='recommended/bin/archivey'
commands=[['--version'],['list','fixtures/basic.zip'],['list','fixtures/basic.tar.gz'],['extract','fixtures/basic.zip','-d','cli-out-zip'],['extract','fixtures/basic.tar.gz','-d','cli-out-tar'],['extract','fixtures/traversal.zip','-d','cli-out-evil'],['extract','fixtures/bomb.zip','-d','cli-out-bomb'],['test','fixtures/crc.zip'],['test','fixtures/truncated.zip'],['test','fixtures/truncated.tar.gz']]
for dest in Path('.').glob('cli-out-*'): shutil.rmtree(dest)
for args in commands:
 p=subprocess.run([exe]+args,capture_output=True,text=True)
 print('$ archivey '+' '.join(args)+'\nexit='+str(p.returncode)+'\n'+p.stdout+p.stderr)
# Format-specific CLI alternative, both commands are shipped with Python.
for args in [['-m','zipfile','-l','fixtures/basic.zip'],['-m','zipfile','-e','fixtures/basic.zip','stdlib-cli-zip'],['-m','tarfile','-l','fixtures/basic.tar.gz'],['-m','tarfile','-e','fixtures/basic.tar.gz','stdlib-cli-tar']]:
 p=subprocess.run([sys.executable]+args,capture_output=True,text=True)
 print('$ python '+' '.join(args)+'\nexit='+str(p.returncode)+'\n'+p.stdout+p.stderr)
```

All four standard-library CLI commands exited 0. Python 3.12’s TAR extraction command also emitted:

```text
DeprecationWarning: Python 3.14 will, by default, filter extracted tar archives and reject files or modify their metadata. Use the filter argument to control this behavior.
```

`edge.py`:

```python
import archivey, zipfile, random, subprocess, shutil
from pathlib import Path
# Below the ratio threshold, deliberately not compressible.
with zipfile.ZipFile('fixtures/read-cap.zip','w',compression=zipfile.ZIP_DEFLATED) as z:
 z.writestr('data',random.Random(7).randbytes(8*2**20))
cfg=archivey.ArchiveyConfig(extraction_limits=archivey.ExtractionLimits(max_extracted_bytes=1024))
with archivey.open_archive('fixtures/read-cap.zip',config=cfg) as a:
 print('read bytes with 1024-byte extraction cap:',len(a.read('data')))
try:
 with archivey.open_archive('fixtures/bad-trailer.tar.gz') as a:
  e=a.verify_all()[0][1]
  print('gzip exception:',type(e).__name__,'is CorruptionError:',isinstance(e,archivey.CorruptionError),str(e))
except Exception as e: print(type(e).__name__,str(e))
for dest in ['dry-empty','dry-existing']: shutil.rmtree(dest,ignore_errors=True)
Path('dry-existing').mkdir(); Path('dry-existing/hello.txt').write_bytes(b'existing')
for dest in ['dry-empty','dry-existing']:
 c=['recommended/bin/archivey','extract','fixtures/basic.zip','-d',dest,'--dry-run','--overwrite','error']
 p=subprocess.run(c,capture_output=True,text=True)
 print(' '.join(c),'exit',p.returncode); print(p.stdout+p.stderr)
print('retained existing:',Path('dry-existing/hello.txt').read_bytes())
```

