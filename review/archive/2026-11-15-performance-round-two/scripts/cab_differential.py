import io, hashlib, itertools, json, struct
from tests.cab_util import CabFile, CabFolder, write_cab
from archivey import open_archive
import cabexperiment as c

raw = write_cab(
    [CabFile(f"f{i}", bytes([i + 1]) * 20000) for i in range(6)], [CabFolder("mszip")]
)
pos = struct.unpack_from("<I", raw, 36)[0]
blocks = []
while pos < len(raw):
    checksum, stored, decoded = struct.unpack_from("<IHH", raw, pos)
    blocks.append(pos)
    pos += 8 + stored
variants = [("clean", raw)]
for i, p in enumerate(blocks):
    for kind in ["absent", "bad"]:
        b = bytearray(raw)
        struct.pack_into("<I", b, p, 0 if kind == "absent" else 1)
        variants.append((f"{kind}-{i}", bytes(b)))
    for n in [p + 3, p + 8, p + 10]:
        variants.append((f"cut-{n}", raw[:n]))


def trace(data, mode, streaming):
    c.patch(mode)
    events = []
    try:
        with open_archive(io.BytesIO(data), streaming=streaming) as a:
            for m, s in a.stream_members():
                events.append(
                    ("member", m.name, m.size, str(m.verifiable), str(m.verified))
                )
                for n in [0, 1, 4096, -1, 1]:
                    try:
                        b = s.read(n)
                    except Exception as e:
                        events.append(("error", n, type(e).__name__, str(e)))
                        break
                    events.append(
                        (
                            "read",
                            n,
                            len(b),
                            hashlib.sha256(b).hexdigest(),
                            str(m.verifiable),
                            str(m.verified),
                        )
                    )
            events.append(("diagnostics", repr(a.diagnostics)))
    except Exception as e:
        events.append(("outer", type(e).__name__, str(e)))
    return events


for label, data in variants:
    for streaming in [False, True]:
        old = trace(data, "old", streaming)
        new = trace(data, "new", streaming)
        assert old == new, (label, streaming, old, new)
for flags in itertools.product([False, True], repeat=8):
    first = next((i for i, x in enumerate(flags) if not x), None)
    for end in range(8):
        assert all(flags[: end + 1]) == (first is None or end < first)
print(
    json.dumps(
        {
            "archive_variants": len(variants),
            "trace_pairs": len(variants) * 2,
            "presence_vectors": 256,
            "result": "equal",
        }
    )
)
