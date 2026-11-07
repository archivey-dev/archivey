"""Test oracle for detection cost: does a receipt stay inside the budget it ran under?

The library never asks this question; the tests do, to prove that detection reads and
decodes no more than its :class:`~archivey.detection_cost.DetectionBudget` declared.
"""

from __future__ import annotations

from archivey.detection_cost import DetectionBudget, DetectionCostReceipt
from archivey.internal.detection import TAIL_PROBE_ALLOWANCE, validator_allowance
from archivey.internal.sfx import LAYOUT_PREFIX
from archivey.internal.streams.codecs.brotli_framing import (
    CHAIN_HEADER_READ,
    CHAIN_MAX_LINKS,
)


def trailer_allowance() -> int:
    """Bytes a cheap trailer read may add on top of the prefix/far/scan ceiling.

    One read per distinct trailer length. The block sits at the end of the source,
    so it is not inside the scan window, and it has no budget field of its own.
    """
    from archivey.internal.registry import get_registry

    return sum({entry.length for entry in get_registry().trailer_entries()})


def within_budget(receipt: DetectionCostReceipt, budget: DetectionBudget) -> bool:
    """Whether aggregate measured work in ``receipt`` stays inside ``budget``'s limits.

    Seek-based content-probe ``read_at`` charges ``unique_bytes_read`` without growing
    the prefix. Those bytes are allowed up to ``CHAIN_MAX_LINKS * CHAIN_HEADER_READ``,
    the Brotli walk's own cap, on top of the prefix/far/scan ceiling. The Brotli chain
    decode reads ``[0, n)`` only when ``n`` is within that ceiling, and takes what the
    prefix holds from the prefix. A trailer block is the same kind of extra read:
    :func:`trailer_allowance` bytes, once. So is an SFX hit validator reading the
    header of a candidate near the scan window's end: up to
    :func:`~archivey.internal.detection.validator_allowance` bytes past
    ``max_scan_bytes``, and only when the receipt shows a scan ran. The PE tail probe
    (``TAIL_PROBE_ALLOWANCE``: its search span and two record parts) is granted on
    the same condition.

    ``prefix_bytes`` is the one counter not compared: it bills overlapping requests in
    full, so ``unique_bytes_read`` stands in for it.

    The budget applies per pass: every limit is multiplied by ``receipt.passes``, so a
    receipt that followed a stub to its sibling volume is judged against two budgets,
    the work each pass was allowed. The validator allowance is multiplied too: the
    second pass reads the sibling volume, a different source with its own prefix, so
    each pass can pay it.
    """
    # ``passes`` is 1 or 2 from ``detect_format``; a receipt built by hand can carry
    # anything, and fewer than one pass is judged as one.
    n = max(1, receipt.passes)
    probe_allowance = CHAIN_MAX_LINKS * CHAIN_HEADER_READ
    # An executable's headers are read from their whole span under any prefix
    # budget, so the layout matches the one a forced ``format=`` reads.
    read_ceiling = max(
        budget.max_prefix_bytes,
        budget.max_far_bytes,
        budget.max_scan_bytes,
        LAYOUT_PREFIX,
    )
    # The PE tail probe runs only after an SFX scan, as the validator reads do; a
    # receipt cannot show that it ran, so a scan earns both allowances.
    sfx_allowance = (
        validator_allowance(budget) + TAIL_PROBE_ALLOWANCE
        if receipt.scanned_bytes > 0
        else 0
    )
    return (
        receipt.unique_bytes_read
        <= n * (read_ceiling + probe_allowance + trailer_allowance() + sfx_allowance)
        and receipt.far_bytes <= n * budget.max_far_bytes
        and receipt.scanned_bytes <= n * budget.max_scan_bytes
        and receipt.decode_input <= n * budget.max_decode_input
        and receipt.decode_output <= n * budget.max_decode_output
    )
