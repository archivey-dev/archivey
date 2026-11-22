## 1. Library

- [x] 1.1 `SourceProgress` and `ArchiveyConfig.on_source_read`, exported and checked
- [x] 1.2 Local reports from `ArchiveSource`, about once per MiB
- [x] 1.3 Request reports from `RangeSource._cat`
- [x] 1.4 Wiring in `open_archive()` and `open_stream()`, outer source only
- [x] 1.5 Tests: local, URL, raise, unset, nested

## 2. HTTP byte progress

- [x] 2.1 The HTTP adapter reads an answer one `sync()` per chunk and reports inside a
  request

## 3. CLI and docs

- [x] 3.1 URL status line on stderr for every verb (tqdm, after 0.5 s,
  `--hide-progress`)
- [x] 3.2 `test` and `extract` use the input position when the output total is unknown
- [x] 3.3 Docs: "Showing progress" in the reading guide and the remote archives page
