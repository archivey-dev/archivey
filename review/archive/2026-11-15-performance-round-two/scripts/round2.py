import argparse, cProfile, gc, gzip, io, json, lzma, os, random, statistics, sys, tarfile, tempfile, time, zipfile
from pathlib import Path
from archivey import open_archive

ROOT = Path(
    os.environ.get(
        "ROUND2_DIR", Path(tempfile.gettempdir()) / "archivey-performance-round-two"
    )
).resolve()
ROOT.mkdir(parents=True, exist_ok=True)


def build():
    r = random.Random(1)
    data = [
        (f"d{i % 40}/s{i % 7}/f{i}.txt", r.randbytes(r.randint(20, 600)))
        for i in range(4000)
    ]
    if not (ROOT / "small.zip").exists():
        with zipfile.ZipFile(ROOT / "small.zip", "w", zipfile.ZIP_DEFLATED) as z:
            for n, b in data:
                z.writestr(n, b)
    for filename, items in [
        ("small.tar", data),
        ("list.tar", [(f"d{i % 50}/f{i}.bin", b"x" * 32) for i in range(20000)]),
        (
            "large.tar",
            [
                (f"f{i}.bin", random.Random(i).randbytes(524288) + b"x" * 524288)
                for i in range(64)
            ],
        ),
    ]:
        p = ROOT / filename
        if not p.exists():
            with tarfile.open(p, "w", format=tarfile.USTAR_FORMAT) as t:
                for n, b in items:
                    info = tarfile.TarInfo(n)
                    info.size = len(b)
                    t.addfile(info, io.BytesIO(b))
    for base in ["small", "large"]:
        raw = (ROOT / (base + ".tar")).read_bytes()
        for suffix, encode in [("gz", gzip.compress), ("xz", lzma.compress)]:
            p = ROOT / (base + ".tar." + suffix)
            if not p.exists():
                p.write_bytes(encode(raw))
    if not (ROOT / "small.7z").exists():
        import py7zr

        with py7zr.SevenZipFile(ROOT / "small.7z", "w") as z:
            for n, b in data:
                z.writestr(b, n)
    if not (ROOT / "small.cab").exists():
        from tests.cab_util import write_cab, CabFolder, CabFile

        (ROOT / "small.cab").write_bytes(
            write_cab(
                [CabFile(n.replace("/", "\\"), b) for n, b in data],
                [CabFolder("mszip")],
            )
        )


class Pipe(io.RawIOBase):
    def __init__(self, p):
        self.f = open(p, "rb")

    def readable(self):
        return True

    def read(self, n=-1):
        return self.f.read(n)

    def readinto(self, b):
        return self.f.readinto(b)

    def close(self):
        self.f.close()
        super().close()


CASES = {
    "zip_list": ("small.zip", "list", 4000),
    "zip_stream": ("small.zip", "stream", 4000),
    "tar_list": ("list.tar", "list", 20000),
    "gz_path": ("small.tar.gz", "stream", 4000),
    "xz_path": ("small.tar.xz", "stream", 4000),
    "gz_pipe": ("small.tar.gz", "pipe", 4000),
    "xz_pipe": ("small.tar.xz", "pipe", 4000),
    "cab_read": ("small.cab", "stream", 4000),
    "7z_read": ("small.7z", "stream", 4000),
    "gz_reverse": ("large.tar.gz", "reverse", 64),
    "xz_reverse": ("large.tar.xz", "reverse", 64),
    "zip_extract": ("small.zip", "extract", 4000),
}


def run(case):
    name, op, count = CASES[case]
    p = ROOT / name
    src = Pipe(p) if op == "pipe" else p
    total = 0
    try:
        with open_archive(src, **({"streaming": True} if op == "pipe" else {})) as a:
            if op == "list":
                total = len(a.members())
            elif op == "extract":
                with tempfile.TemporaryDirectory(dir=ROOT) as d:
                    a.extract_all(d)
            elif op == "reverse":
                for m in reversed(a.members()):
                    with a.open(m) as s:
                        total += len(s.read())
            else:
                for m, s in a.stream_members():
                    if s is not None:
                        total += len(s.read())
    finally:
        if op == "pipe":
            src.close()
    return total


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", choices=CASES)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--profile", action="store_true")
    ap.add_argument("--loop", type=int)
    ap.add_argument("--build", action="store_true")
    args = ap.parse_args()
    if args.build:
        build()
    cases = [args.case] if args.case else CASES
    for case in cases:
        result = run(case)
        gc.collect()
        gc.freeze()
        gc.disable()
        if args.profile:
            pr = cProfile.Profile()
            pr.runcall(run, case)
            pr.dump_stats(str(ROOT / (case + ".prof")))
        vals = []
        for _ in range(args.loop or args.runs):
            t = time.perf_counter()
            check = run(case)
            vals.append(time.perf_counter() - t)
            assert check == result
        row = dict(
            case=case,
            count=CASES[case][2],
            result=result,
            seconds=vals,
            median_us=statistics.median(vals) * 1e6 / CASES[case][2],
        )
        print(json.dumps(row), flush=True)
