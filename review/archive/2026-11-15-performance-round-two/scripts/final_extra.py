import gc, io, json, random, statistics, time, tempfile, sys, tarfile, zipfile, cProfile
from pathlib import Path
import round2 as b


def timed(fn, n=7):
    fn()
    gc.collect()
    gc.freeze()
    gc.disable()
    vals = []
    for _ in range(n):
        start = time.perf_counter()
        fn()
        vals.append(time.perf_counter() - start)
    return {"median_s": statistics.median(vals), "seconds": vals}


def pairs(old, new, count, n=15):
    old()
    new()
    gc.collect()
    gc.freeze()
    gc.disable()
    vals = {"old": [], "new": []}
    for i in range(n):
        for k, fn in (
            [("old", old), ("new", new)] if i % 2 else [("new", new), ("old", old)]
        ):
            start = time.perf_counter()
            fn()
            vals[k].append((time.perf_counter() - start) * 1e6 / count)
    return {
        "median_us": {k: statistics.median(v) for k, v in vals.items()},
        "times": vals,
    }


if sys.argv[1] == "cab":
    import cabexperiment as c

    def run(mode):
        c.patch(mode)
        return b.run("cab_read")

    print(
        json.dumps(
            {
                "case": "cab_prefix",
                "pairs": pairs(lambda: run("old"), lambda: run("new"), 4000),
            }
        ),
        flush=True,
    )
else:
    from archivey import open_archive
    from archivey.internal.streams import codecs
    from archivey.internal.config import replace

    original = codecs.open_codec_stream

    def restart(on):
        def wrapper(*args, **kw):
            kw["config"] = replace(kw["config"], restart_points=on)
            return original(*args, **kw)

        codecs.open_codec_stream = wrapper

    for case in ["gz_path", "xz_path"]:

        def run(on):
            restart(on)
            return b.run(case)

        print(
            json.dumps(
                {
                    "case": case + "_restart",
                    "pairs": pairs(lambda: run(False), lambda: run(True), 4000),
                }
            ),
            flush=True,
        )

        def op(on):
            restart(on)
            with open_archive(b.ROOT / b.CASES[case][0]):
                pass

        print(
            json.dumps(
                {
                    "case": case + "_open",
                    "pairs": pairs(lambda: op(False), lambda: op(True), 1, 100),
                }
            ),
            flush=True,
        )
    codecs.open_codec_stream = original
    for case in ["zip_list", "zip_stream", "tar_list"]:

        def op():
            if case == "tar_list":
                with tarfile.open(b.ROOT / "list.tar") as t:
                    t.getmembers()
            elif case == "zip_list":
                with zipfile.ZipFile(b.ROOT / "small.zip") as z:
                    z.infolist()
            else:
                with zipfile.ZipFile(b.ROOT / "small.zip") as z:
                    for m in z.infolist():
                        z.read(m)

        print(json.dumps({"case": case + "_stdlib", **timed(op)}), flush=True)
    vals = []
    for i in range(8):
        with tempfile.TemporaryDirectory(dir=b.ROOT) as d:
            start = time.perf_counter()
            with open_archive(b.ROOT / "small.zip") as a:
                a.extract_all(d)
            elapsed = time.perf_counter() - start
            if i:
                vals.append(elapsed)
    print(
        json.dumps(
            {
                "case": "zip_extract_without_cleanup",
                "median_us": statistics.median(vals) * 1e6 / 4000,
                "seconds": vals,
            }
        ),
        flush=True,
    )
    with tempfile.TemporaryDirectory(dir=b.ROOT) as d:

        def op():
            with open_archive(b.ROOT / "small.zip") as a:
                a.extract_all(d)

        pr = cProfile.Profile()
        pr.runcall(op)
        pr.dump_stats(str(b.ROOT / "extract_only.prof"))
