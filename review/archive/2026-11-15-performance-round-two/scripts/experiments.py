import inspect, textwrap, random, time, statistics, json, gc, sys
import round2 as b
from archivey.internal.streams import verification as v
from archivey.internal import bomb_tracker as r
from archivey.internal.backends import tar_parser as t
from archivey.internal.streams import verify as mv
from archivey.internal import format_adapter as fa

ORIGINAL = (
    v.VerificationProofs.doubt_only,
    r._RatioGuard.read,
    t._byte_sum,
    mv.MemberVerifier.proofs,
    fa.IndexedReaderAdapter._hint_ranges,
)


def patch(which):
    (
        v.VerificationProofs.doubt_only,
        r._RatioGuard.read,
        t._byte_sum,
        mv.MemberVerifier.proofs,
        fa.IndexedReaderAdapter._hint_ranges,
    ) = ORIGINAL
    if which in ("proof", "proof8", "all"):
        doubt = v.VerificationProofs(key_in_doubt=True)

        def doubt_only(self):
            return doubt if self.key_in_doubt else v.NO_PROOFS

        v.VerificationProofs.doubt_only = doubt_only
    if which in ("proof8", "all"):
        table = tuple(
            tuple(
                tuple(
                    v.VerificationProofs(ended=e, content=c, content_possible=p)
                    for p in (False, True)
                )
                for c in (False, True)
            )
            for e in (False, True)
        )

        def proofs(self):
            return table[self._ended_clean][self._digest_matched][bool(self._expected)]

        mv.MemberVerifier.proofs = proofs
    if which in ("ratio", "all"):
        src = (
            textwrap.dedent(inspect.getsource(ORIGINAL[1]))
            .replace("@override\n", "")
            .replace(
                "0 <= n <= max(_GUARD_STEP, self._room())",
                "0 <= n and (n <= _GUARD_STEP or n <= self._room())",
            )
        )
        ns = {}
        exec(compile(src, "ratio-experiment", "exec"), r.__dict__, ns)
        r._RatioGuard.read = ns["read"]
    if which in ("hints", "all"):
        src = textwrap.dedent(inspect.getsource(ORIGINAL[4]))
        start = src.index("    if not isinstance(ranges, tuple) or not all(")
        end = src.index("        with suppress(Exception):", start)
        src = (
            src[:start]
            + "    valid = isinstance(ranges, tuple)\n    if valid:\n        for span in ranges:\n            if not isinstance(span, tuple) or len(span) != 2:\n                valid = False\n                break\n            for x in span:\n                if not isinstance(x, int) or isinstance(x, bool):\n                    valid = False\n                    break\n            if not valid:\n                break\n    if not valid:\n"
            + src[end:]
        )
        ns = {}
        exec(compile(src, "hints-experiment", "exec"), fa.__dict__, ns)
        fa.IndexedReaderAdapter._hint_ranges = ns["_hint_ranges"]
    if which in ("sum", "all"):
        old = ORIGINAL[2]

        def byte_sum(data):
            if len(data) == 512 and data.isascii():
                return (t.zlib.adler32(data) & 65535) - 1
            return old(data)

        t._byte_sum = byte_sum


if __name__ == "__main__":
    which = sys.argv[1]
    cases = sys.argv[2:] or [
        "zip_stream",
        "tar_list",
        "gz_path",
        "xz_path",
        "cab_read",
        "7z_read",
    ]
    result = {}
    for case in cases:
        patch("none")
        expected = b.run(case)
        patch(which)
        assert b.run(case) == expected
        gc.collect()
        gc.freeze()
        gc.disable()
        times = {"none": [], "patch": []}
        rng = random.Random(0)
        for i in range(15):
            order = ["none", "patch"]
            rng.shuffle(order)
            for name in order:
                patch(which if name == "patch" else "none")
                start = time.perf_counter()
                assert b.run(case) == expected
                times[name].append(
                    (time.perf_counter() - start) * 1e6 / b.CASES[case][2]
                )
        print(
            json.dumps(
                dict(
                    patch=which,
                    case=case,
                    times=times,
                    median={k: statistics.median(a) for k, a in times.items()},
                    minimum={k: min(a) for k, a in times.items()},
                )
            ),
            flush=True,
        )
