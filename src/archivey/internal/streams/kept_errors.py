"""Errors a stream keeps and raises again on every later call.

A stream that failed keeps its error, and every later read raises it again: a
decoder's recorded death (``DecoderChild``), a decompressor's deferred end error
(``DecompressorStream``), a member stream's content verdict and its failed lazy open
(``ArchiveStreamImpl``). The kept instance must never be the one raised. A raise
attaches a traceback, whose frames hold the stream, and the stream holds the
instance: a cycle that only the garbage collector breaks, and until it runs, every
local of those frames stays alive, a decoder holding a leased child process among
them. ``f_back`` extends that to the caller's frames.

So a stream keeps a :class:`KeptError`: a copy that was never raised, and the first
raise's traceback as text. Each later raise is a fresh copy whose cause is an
:class:`EarlierRaise` holding that text, so a printed error shows where it was first
raised and where it was raised again, and pins no frame.
"""

from __future__ import annotations

import copy
import traceback
from dataclasses import dataclass
from typing import NoReturn, TypeVar

_E = TypeVar("_E", bound=BaseException)


class EarlierRaise(Exception):
    """The cause of an error raised again: where it was first raised, as text."""


def unraised(exc: _E) -> _E:
    """A copy of ``exc`` that has never been raised, or ``exc`` itself when its type
    cannot be rebuilt from its arguments (the cycle is then kept).

    The copy is shallow: a mutable attribute (``__notes__``, say) is shared with
    ``exc``. It has no traceback, cause or context.
    """
    try:
        return copy.copy(exc)
    except Exception:  # noqa: BLE001 - a type that copy cannot rebuild: keep the cycle
        return exc


@dataclass(frozen=True)
class KeptError:
    """An error a stream raised, kept to raise again without its frames."""

    error: BaseException
    """A copy of the error that was never raised."""

    first_raise: str
    """The first raise's traceback, its causes included, as text."""

    @classmethod
    def of(cls, raised: BaseException) -> KeptError:
        """Keep ``raised``, which is being raised now (its traceback so far)."""
        return cls(unraised(raised), "".join(traceback.format_exception(raised)))

    def raise_again(self) -> NoReturn:
        """Raise a fresh copy of the error, caused by where it was first raised."""
        raise unraised(self.error) from EarlierRaise(
            f"first raised here:\n{self.first_raise}"
        )
