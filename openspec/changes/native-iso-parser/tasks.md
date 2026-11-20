## 1. Parser

- [x] 1.1 `iso9660.py`: descriptors, directory records, SUSP/Rock Ridge, multi-extent
  joining, padding notes, cut detection, budget protocol, path-table read hints
- [x] 1.2 Differential tests against pycdlib on pycdlib, xorriso and genisoimage images;
  bit-flip campaign; damage tests

## 2. Reader

- [x] 2.1 `IsoReader` on `IsoVolume`; remove the pycdlib hooks, the raw re-parse, the
  handle lock and the error net
- [x] 2.2 Update the ISO tests whose expectations named pycdlib behaviour
- [x] 2.3 `pycdlib` out of `[recommended]` and `[free-threaded]`; ISO registered with no
  optional dependency; specs that used ISO as the missing-package example move to
  another format
- [x] 2.4 Handbook (`dev-docs/formats/iso.md`) and user docs
- [x] 2.5 Check real images: the Sintel Blu-ray and a Windows 98 ISO by URL, an Ubuntu
  4.10 and a Debian 12 netinst image, and libarchive's ISO test images. The Windows 11
  image's listed tree is UDF, whose parser this change does not touch
- [ ] 2.6 On archive: the `format-iso` Purpose and Related specs no longer name
  `pycdlib`
