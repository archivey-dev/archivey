## Decisions

Unknown-size seekable sources use the existing `read_at` contract: short/empty
means EOF; `None` means the read was declined. Pipe observations carry a separate
EOF flag. A short arrival is not EOF, and optional end checks do not wait for
another byte or closure. A non-last block requires a successor header.
A declared end checks its last byte and the absence of a following byte, so a
truncated final metadata block is not confused with an exact end.

The workspace owns source policy. Cheap seeks skip literal bodies; a pipe or an
expensive-seek source must grow its replay buffer. Seekable sources keep their
existing bounded read-ahead. Only forward-only sources use the new numeric
allowance, which works with custom budgets.
Whole-source completion keeps its separate allowance. Header reads and the chain
decode share the forward policy; a refused read does not spend decode input.

The existing eight-link limit remains. Cheap header seeks retain their reach at
any offset; buffer growth and chain decodes stop at 1 MiB. A final unknown-size end
check adds at most two bytes to the header-read allowance in the receipt oracle.
No limit exhaustion proves invalid framing.

An enabled pipe chain decode feeds arrived chunks to one decoder. It continues
through short arrivals until an error, decoder completion, or its input/output
bound. The sample view does not gather a full read before feeding the decoder.
The target input ceiling is charged first and is not refunded on early completion.
A finished decoder ends the view without an optional pipe read.

## Encoder evidence

Brotli 1.2.1 round-tripped 108 streams across qualities 0–11, window sizes 16 and
22, random/text/mixed input, streaming, and flush boundaries. It emitted literal
blocks of 300,123 and 1,200,123 bytes. Flushes emitted repeated 17,003-byte blocks;
flushing each `x` emitted sixteen one-byte literals at qualities 0, 1, 5, and 11.
The reference encoder's `MakeUncompressedStream` permits blocks up to 16 MiB.
Neither a 128 KiB size threshold nor an entropy rule can safely reject a stream.

## Verification

The public regression failed before implementation on unknown-size seekable
sources under `FAST` / `BALANCED`, and on forward-only sources under `THOROUGH`.
Tests cover custom forward allowances, EOF versus declined reads, large valid
literal blocks, compressed-block damage, and held-open pipes under every preset, on Python 3.11 and 3.15.
