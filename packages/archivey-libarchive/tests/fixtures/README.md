# Fixtures

The `.lzh` files are libarchive's own test archives (`libarchive/test/test_read_format_lha_*.lzh.uu`
at tag v3.7.2, uudecoded), under libarchive's BSD 2-clause license. Despite its name,
`lha_lh0.lzh` stores its files with `-lh5-`; `tests/test_lha.py` builds a stored (`-lh0-`)
archive itself.
