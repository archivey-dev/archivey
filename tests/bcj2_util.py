"""Writes BCJ2 streams for the tests: the four streams 7-Zip's BCJ2 encoder gives
for x86-looking data, with random convert decisions and targets."""

from __future__ import annotations

import random


class _RangeEncoder:
    """LZMA's range encoder, with the probability model BCJ2 decodes with."""

    def __init__(self) -> None:
        self.low, self.range, self.cache, self.cache_size = 0, 0xFFFFFFFF, 0, 1
        self.out = bytearray()
        self.probs = [1024] * 258

    def _shift_low(self) -> None:
        if self.low < 0xFF000000 or self.low > 0xFFFFFFFF:
            carry, temp = self.low >> 32, self.cache
            while True:
                self.out.append((temp + carry) & 0xFF)
                temp = 0xFF
                self.cache_size -= 1
                if self.cache_size == 0:
                    break
            self.cache = (self.low >> 24) & 0xFF
        self.cache_size += 1
        self.low = (self.low & 0x00FFFFFF) << 8

    def bit(self, context: int, bit: bool) -> None:
        p = self.probs[context]
        bound = (self.range >> 11) * p
        if bit:
            self.low += bound
            self.range -= bound
            self.probs[context] = p - (p >> 5)
        else:
            self.range = bound
            self.probs[context] = p + ((2048 - p) >> 5)
        while self.range < 1 << 24:
            self.range <<= 8
            self._shift_low()

    def finish(self) -> bytes:
        for _ in range(5):
            self._shift_low()
        return bytes(self.out)


def bcj2_encode(rng: random.Random, size: int) -> tuple[bytes, ...]:
    """Valid BCJ2 streams for ``size`` bytes of x86-looking output, with random
    convert decisions and targets: the four streams end where the decoder stops."""
    main, call, jump = bytearray(), bytearray(), bytearray()
    enc = _RangeEncoder()
    out_len, prev = 0, 0
    while out_len < size:
        b = (
            rng.choice(b"\xe8\xe9\x0f\x85")
            if rng.random() < 0.2
            else rng.randrange(256)
        )
        main.append(b)
        out_len += 1
        candidate = b in (0xE8, 0xE9) or (b & 0xF0 == 0x80 and prev == 0x0F)
        if not candidate or out_len == size:
            prev = b
            continue
        context = prev if b == 0xE8 else 256 if b == 0xE9 else 257
        convert = rng.random() < 0.5
        enc.bit(context, convert)
        if not convert:
            prev = b
            continue
        target = rng.getrandbits(32)
        dest = (target - (out_len + 4)) & 0xFFFFFFFF
        (call if b == 0xE8 else jump).extend(target.to_bytes(4, "big"))
        out_len = min(size, out_len + 4)
        prev = dest >> 24
    return bytes(main), bytes(call), bytes(jump), enc.finish()
