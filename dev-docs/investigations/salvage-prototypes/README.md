# Salvage prototypes

Throwaway code behind the measurements in [`../salvage-design.md`](../salvage-design.md)
§3. It is not archivey code, is not linted or tested, and hard-codes its working
directory (`/tmp/claude-0/sv`, with the archives in `a/` and the damaged copies in `d/`).
Keep it only as the record of how the numbers were made.

| File | What it does |
| --- | --- |
| `damage.py` | Writes the 20 damaged copies of each archive (§15.2) |
| `eval_archivey.py` | Reads one archive with archivey: a `stream_members()` pass that reads every member |
| `eval_ref.py` | Extracts with `unzip`, GNU tar, 7-Zip, `unrar` or `ar`, and hashes what was written |
| `drive.py` | Runs every reader on every copy, in parallel; results go to `results.json` |
| `score.py` | Counts members whose SHA-1 equals the intact archive's, per copy and reader |
| `common.py` | Output format and the TAR header scan (`tar_scan`), shared by the prototypes |
| `salvage_zipscan.py` | ZIP: scan for local headers, keep members whose CRC matches |
| `salvage_tarscan.py` | TAR: 512-byte blocks and `ustar` at any byte, checksum |
| `salvage_gzresync.py`, `deflate_resync.py` | gzip: DEFLATE block restart by trial inflate, determined bytes by two window fillers, then the TAR scan |
| `salvage_bz2blocks.py` | bzip2: blocks by magic at any bit offset, each decoded alone, then the TAR scan |
| `salvage_xzblocks.py` | xz: block headers by CRC, each block decoded and checked alone, then the TAR scan |
| `salvage_7zlzma2.py` | 7z: LZMA2 dictionary-reset parts when the header reads; raw LZMA2 from offset 32 when it does not |
| `salvage_rarsearch.py` | RAR5: header CRC at every byte, stored members read and checked by their data CRC |
| `salvage_isotrees.py` | ISO: walk the primary (Rock Ridge names) and Joliet trees, keep the union |
