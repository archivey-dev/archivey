"""Apple Data Compression (UDIF run type 0x80000004), as described by dmg2img/7-Zip docs."""


class AdcError(Exception):
    pass


def decompress(src: bytes, max_out: int) -> bytes:
    out = bytearray()
    i, n = 0, len(src)
    while i < n and len(out) < max_out:
        b = src[i]
        if b & 0x80:
            cnt = (b & 0x7F) + 1
            if i + 1 + cnt > n:
                raise AdcError("literal run past end")
            out += src[i + 1:i + 1 + cnt]
            i += 1 + cnt
            continue
        if b & 0x40:
            if i + 3 > n:
                raise AdcError("truncated")
            length = (b & 0x3F) + 4
            dist = (src[i + 1] << 8 | src[i + 2]) + 1
            i += 3
        else:
            if i + 2 > n:
                raise AdcError("truncated")
            length = ((b & 0x3C) >> 2) + 3
            dist = ((b & 0x03) << 8 | src[i + 1]) + 1
            i += 2
        if dist > len(out):
            raise AdcError("distance before start")
        start = len(out) - dist
        for k in range(length):
            out.append(out[start + k])
    if len(out) > max_out:
        raise AdcError("output larger than run")
    return bytes(out)
