## Implementation

- [x] 1.1 Reproduce the inconsistent result and run the public regression red.
- [x] 1.2 Walk unknown-size framing without treating declined reads as EOF.
- [x] 1.3 Apply numeric forward budgets to probe header reads and chain decodes.
- [x] 1.4 Update maintainer contracts and remove the resolved known defect.

## Verification

- [x] 2.1 Run focused regressions, including real encoder output and held-open pipes.
- [x] 2.2 Run `scripts/check.sh --fix` and `scripts/test.sh --all-configs`;
  record runner restrictions and corrected harness reruns in the pull request.
- [x] 2.3 Run `openspec validate --strict brotli-unknown-length-probes`.
