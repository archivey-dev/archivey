# Commons Compress pins

`expected.json` holds the pins for `tests/test_commons_compress_corpus.py`. Each file in
Apache Commons Compress's `src/test/resources` has three summaries: what Commons
Compress read (`cc`), what archivey reads from a path (`path`), and what archivey reads
from a pipe (`pipe`, only when it differs from `path`). A summary is the format or the
error class, the member count, and a digest of the members' names, types, bytes read and
CRC-32s. It names files and CRCs only and holds none of their contents.

`scripts/gen_commons_compress_expected.py` rewrites it. Its docstring says how to get
the Commons Compress listing that the script needs. The `commons_compress` key records
the commit the pins were made from.
