## ADDED Requirements

### Requirement: The PE tail probe is bounded and recorded as its own tier

The tail probe of *A ZIP behind a PE's overlay is found from its end record*
(`format-detection`) SHALL read at most the 65 558-byte search span plus the fixed parts of
two records (the first central header and the local header it names). Those bytes SHALL
count in `unique_bytes_read` and SHALL NOT count in `scanned_bytes`, so `scanned_bytes`
stays within `max_scan_bytes`. The probe has no budget field of its own: it SHALL run only
when `max_scan_bytes` is above 0, and SHALL be recorded under the tier name `sfx_tail`
as *not enabled by policy* when it is 0, and as *capability unavailable* when the tail
cannot be read cheaply. A source the gate excludes (no PE layout, no overlay past the
window) SHALL record nothing for `sfx_tail`: there was nothing for it to look for.

#### Scenario: tail probe receipt

| Case | Expected |
| --- | --- |
| Gated PE, default budget, ZIP found | `unique_bytes_read` ≤ scan ceiling + probe allowance + trailer + tail allowance; `scanned_bytes` ≤ `max_scan_bytes` |
| Gated PE under `FAST` | Probe runs; same bounds under `FAST`'s scan ceiling |
| Ordinary signed PE larger than the window | No `sfx_tail` record; receipt unchanged from today |
