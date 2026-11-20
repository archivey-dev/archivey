## 1. Parser

- [x] 1.1 `iso9660.py`: descriptors, directory records, SUSP/Rock Ridge, multi-extent
  joining, padding notes, cut detection, budget protocol, path-table read hints
- [x] 1.2 Differential tests against pycdlib on pycdlib, xorriso and genisoimage images;
  bit-flip campaign; damage tests

## 2. Reader

- [ ] 2.1 `IsoReader` on `IsoVolume`; remove the pycdlib hooks, the raw re-parse, the
  handle lock and the error net
- [ ] 2.2 Update the ISO tests whose expectations named pycdlib behaviour
- [ ] 2.3 `pycdlib` out of `[recommended]` and `[free-threaded]`; ISO registered with no
  optional dependency; specs that used ISO as the missing-package example move to
  another format
- [ ] 2.4 Handbook (`dev-docs/formats/iso.md`) and user docs
- [ ] 2.5 Check real images: Windows 11, Sintel Blu-ray, a Windows 98 ISO by URL
