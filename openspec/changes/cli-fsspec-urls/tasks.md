## 1. Source resolution

- [ ] 1.1 Add shared CLI source resolution through public fsspec and archivey APIs,
  preserving local-path precedence, stdin rules and literal URL bytes. Recognize
  candidates before importing fsspec, and define unknown first protocols only
  after import. Support chains and registered archive protocols.
- [ ] 1.2 Route shared archive opening, `info` and its detection fallback, `cat
  --outer`, and `test`/`extract --outer` detection through that resolution.
- [ ] 1.3 Preserve local FIFO/device streaming behavior and optional dependency
  imports. Keep remote volume discovery and new CLI options out of scope.

## 2. Names and errors

- [ ] 2.1 Separate extraction's I/O source from its local destination naming.
  Keep percent escapes literal and check stems as safe local segments, including
  raw backslashes, colons and Windows reserved/invalid names.
- [ ] 2.2 Implement a CLI-local copy of the remote URL display policy, with parity
  tests against the internal helper, as for `outer_layer_format`. Add no public
  name. Sanitize chain links and replace exact original-URL occurrences in
  third-party errors and CLI logging before escaping. Build the
  `aiohttp.ClientResponseError` message from `status`, `message` and the
  sanitized label instead of printing the exception text.
- [ ] 2.3 Translate setup dependency `ImportError`, existing archivey/OS errors,
  and HTTP `aiohttp.ClientError` into CLI
  failures during setup and iteration. Leave unlisted exceptions unhandled and
  preserve partial results.

## 3. Verification and documentation

- [ ] 3.1 Add CLI behavior tests for all verbs, aliases, default listing and
  `--outer`, using real fsspec memory sources and a local range-capable HTTP server.
  Add `aiohttp` to the dev dependency group and update `uv.lock`.
  HTTP integration tests skip when aiohttp is absent in the core-only
  leg; dependency-absence tests must still run there.
- [ ] 3.2 Test local precedence without importing fsspec, Windows/UNC paths,
  unknown protocols, literal URL characters, no remote glob/volume discovery,
  sanitized labels, safe smart destinations, explicit `-d`, and missing packages.
  Include unknown schemes with/without fsspec, cache and archive chains, raw
  backslash/colon stems, Windows invalid/reserved names and literal percent escapes.
- [ ] 3.3 Test missing objects, authentication and connection failures, unsupported
  ranges and a source changing during a read. Include a real HTTP 403 during a
  member read on a signed URL whose query contains `%2F`, a signed HTTP 404,
  HTTP failures during iteration and setup, and an unlisted exception
  that must propagate. Check exit codes, URL redaction and partial output.
- [ ] 3.4 Update `docs/cli.md` and `docs/remote.md` with URL examples, HTTP/store
  dependencies, chains, backend credential discovery, the handled exception
  classes, and the limits of exact-URL redaction.
- [ ] 3.5 Run `./scripts/check.sh --fix`, `./scripts/test.sh --all-configs` and
  `uv run python scripts/review/review_prep.py` for the implementation.
- [ ] 3.6 Sync the CLI delta and archive this change when implementation lands;
  mark the fsspec integration change's task 7.3 complete then.
- [ ] 3.7 Run `openspec validate --strict cli-fsspec-urls`.
