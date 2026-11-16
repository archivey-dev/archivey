## 1. Source resolution

- [ ] 1.1 Add shared CLI source resolution through public fsspec and archivey APIs,
  preserving local-path precedence, stdin rules and literal URL bytes.
- [ ] 1.2 Route shared archive opening, `info` and its detection fallback, `cat
  --outer`, and `test`/`extract --outer` detection through that resolution.
- [ ] 1.3 Preserve local FIFO/device streaming behavior and optional dependency
  imports. Keep remote volume discovery and new CLI options out of scope.

## 2. Names and errors

- [ ] 2.1 Separate extraction's I/O source from its local destination naming.
  Apply safe filename/stem rules to URLs, including signed and escaped URLs.
- [ ] 2.2 Reuse the remote display policy through public helpers for CLI labels,
  keeping the CLI's public-API-only constraint.
- [ ] 2.3 Translate known dependency and backend transport exceptions into CLI
  failures, including errors raised during iteration. Preserve partial results.

## 3. Verification and documentation

- [ ] 3.1 Add CLI behavior tests for all verbs, aliases, default listing and
  `--outer`, using real fsspec memory sources and a local range-capable HTTP server.
- [ ] 3.2 Test local precedence without importing fsspec, Windows/UNC paths,
  unknown protocols, literal URL characters, no remote glob/volume discovery,
  sanitized labels, safe smart destinations, explicit `-d`, and missing packages.
- [ ] 3.3 Test missing objects, authentication and connection failures, unsupported
  ranges and a source changing during a read. Check exit codes and partial output.
- [ ] 3.4 Update `docs/cli.md` and `docs/remote.md` with URL examples, HTTP/store
  dependencies, backend credential discovery and the exception-text limitation.
- [ ] 3.5 Run `./scripts/check.sh --fix`, `./scripts/test.sh --all-configs` and
  `uv run python scripts/review/review_prep.py` for the implementation.
- [ ] 3.6 Sync the CLI delta and archive this change when implementation lands;
  mark the fsspec integration change's task 7.3 complete then.
- [ ] 3.7 Run `openspec validate --strict cli-fsspec-urls`.
