import gc, itertools, json, random, statistics, time
from types import SimpleNamespace
from experiments import patch, ORIGINAL
from archivey.internal.streams import verify as mv, verification as v
from archivey.internal.backends import tar_parser as tar
from archivey.internal.format_adapter import IndexedReaderAdapter
from archivey.formats import MemberData
import io


def measure(old, new, number=200000):
    old()
    new()
    gc.collect()
    gc.freeze()
    gc.disable()
    a = []
    b = []
    for i in range(15):
        for f, out in ((old, a), (new, b)) if i % 2 else ((new, b), (old, a)):
            t = time.process_time()
            for _ in range(number):
                f()
            out.append((time.process_time() - t) * 1e6 / number)
    return {
        "old_us": statistics.median(a),
        "new_us": statistics.median(b),
        "old_range": [min(a), max(a)],
        "new_range": [min(b), max(b)],
    }


x = mv.MemberVerifier({}, expected_size=1)
old = lambda: ORIGINAL[3](x)
patch("proof8")
new = lambda: mv.MemberVerifier.proofs(x)
print("proof", json.dumps(measure(old, new)), flush=True)
for e, c, p in itertools.product((False, True), repeat=3):
    x._ended_clean = e
    x._digest_matched = c
    x._expected = {"crc32": b"1234"} if p else {}
    assert old() == new()
for values in itertools.product((False, True), repeat=7):
    x = v.VerificationProofs(*values)
    assert ORIGINAL[0](x) == x.doubt_only()
for name, data in [("ascii", b"x" * 512), ("high", b"\xff" * 512)]:
    patch("sum")
    orig = ORIGINAL[2]
    new = tar._byte_sum
    print(
        "sum_" + name,
        json.dumps(measure(lambda: orig(data), lambda: new(data))),
        flush=True,
    )
    assert new(data) == sum(data)
self = SimpleNamespace(_will_read=lambda a, b: None)
data = MemberData(io.BytesIO(), ranges=((10, 20),))
old = lambda: ORIGINAL[4](self, data)
patch("hints")
new = lambda: IndexedReaderAdapter._hint_ranges(self, data)
print("hint", json.dumps(measure(old, new)), flush=True)
