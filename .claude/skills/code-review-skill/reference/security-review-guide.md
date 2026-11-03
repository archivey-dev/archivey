# Security Review Guide

Security-focused checklist for reviewing changes in a **pure Python archive library**
(read / stream / extract untrusted archives). Prefer this over web/app checklists —
there is no browser UI, SQL/ORM layer, or HTTP API in this project.

Primary references in-repo: `dev-docs/threat-model.md` (§2 Trust boundaries),
`docs/security.md` (§Where the guarantees stop), `docs/extracting.md` (§What each
policy does with unusual members), `VISION.md` (safe-by-default + memory-safe parsing
of hostile input).

## Hostile Archive Input

Archives are untrusted by default. Reviewers should ask whether the change preserves
safety under crafted / truncated / malicious members.

### Path traversal & extraction safety
- [ ] Member paths cannot escape the destination (`../`, absolute paths, drive letters)
- [ ] Symlinks / hardlinks cannot escape or overwrite outside the extract root
- [ ] Destination joins use the library’s safe path helpers — no ad-hoc `os.path.join`
- [ ] Overwrite / collide behavior is explicit and tested
- [ ] “Unsafe” extract modes are opt-in and clearly named (not the default)

### Resource exhaustion (zip / decompression bombs)
- [ ] Compressed → uncompressed expansion is bounded or monitored
- [ ] Nested / recursive archive handling does not open an unbounded bomb chain
- [ ] Large member sizes / sparse files cannot force unbounded memory allocation
- [ ] Streaming paths do not buffer entire members when a stream would suffice

### Parser / format robustness
- [ ] Malformed headers fail with library exceptions — not process crashes
- [ ] Truncated archives surface honest errors (and recoverable members where specified)
- [ ] Integer overflows / huge length fields from headers are rejected
- [ ] Native codec / subprocess helpers (`unrar`, etc.) are not fed unsanitized paths
- [ ] New format parsers inherit the same exception-translation contract as existing ones

## Command Injection & Subprocess

When shelling out (e.g. fixture builders, optional external decompressors):

```python
# ❌ Vulnerable: shell=True with interpolated paths
subprocess.run(f"unrar x {archive} {dest}", shell=True)

# ✅ List args, no shell
subprocess.run(["unrar", "x", "-y", str(archive), str(dest)], check=True)
```

- [ ] No `shell=True` with attacker-influenced strings
- [ ] Arguments are discrete list elements, not concatenated command lines
- [ ] Temp paths and working directories are controlled by the library/tests

## Secrets & Configuration

- [ ] No hardcoded passwords, API tokens, or private keys in source
- [ ] Test passwords for encrypted fixtures are clearly fixture-only (not real secrets)
- [ ] Optional crypto extras do not log passwords or key material
- [ ] CI / scripts reference secrets via env vars when needed

## Cryptography (encrypted archives)

- [ ] Use established primitives via `cryptography` (the `[recommended]` extra) — no
  homemade crypto
- [ ] Password/key handling does not leave secrets in exceptions or `__repr__`
- [ ] Wrong-password paths fail closed with a clear error type
- [ ] RNG for any nonces/salts uses `secrets` / OS CSPRNG — not `random`

```python
# ❌ Weak randomness
token = "".join(str(random.randint(0, 9)) for _ in range(16))

# ✅ Cryptographically secure
import secrets
token = secrets.token_hex(16)
```

## Error Messages & Logging

- [ ] Exceptions do not embed full file contents or password material
- [ ] Logs avoid dumping raw hostile blobs at info/debug in hot paths
- [ ] User-facing errors are actionable without leaking absolute host paths unnecessarily
- [ ] Internal parser details can be logged at debug — not required in every raise message

## Dependency Security

- [ ] New runtime deps are justified (core stays zero-dep)
- [ ] Optional extras match `packaging-and-extras` / `pyproject.toml` contracts
- [ ] Lock / pin story respected for CI (`uv lock` / documented extras)
- [ ] Prefer `uv run` / project tooling over ad-hoc global installs in docs/scripts

```bash
# Python dependency audit (when reviewing dep bumps)
uv run --no-sync pip-audit   # if available in the env
```

## Security Review Severity Levels

| Severity | Description | Action |
|----------|-------------|--------|
| **Critical** | Path escape, arbitrary write, or trivial DoS on default APIs | Block merge |
| **High** | Safety opt-out footgun, unbounded allocation on hostile input | Block merge |
| **Medium** | Defense-in-depth gap, incomplete validation | Should fix / track |
| **Low** | Hardening / clarity | Non-blocking |
| **Info** | Suggestion | Optional |
