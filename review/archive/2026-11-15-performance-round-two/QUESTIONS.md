# Maintainer decisions

The recommended order is verifier proof records, ratio allowance short-circuit, then CAB
checksum-presence summary. No default, public API or guarantee change is proposed.

The CAB proposal adds 8-36 retained bytes per touched folder in exchange for eliminating
repeated prefix scans and tuple slices. Keep that cost explicit when deciding whether to
implement it. The small-corpus wall-time improvement remains noisy.

A larger shared checked-read driver needs a separate prototype and equivalence review.
This report does not recommend committing to that structure before measuring it.

There is no request to weaken verification, limits, error timing, recovery, diagnostics or
concurrency. No unresolved specification conflict was identified by this investigation.
