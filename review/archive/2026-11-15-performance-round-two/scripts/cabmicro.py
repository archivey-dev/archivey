import ast, gc, json, statistics, sys, time, threading
from types import SimpleNamespace
import cabexperiment as c

cab = c.cab
node = next(
    n for n in c.cls.body if isinstance(n, ast.FunctionDef) and n.name == "_block_table"
)
ns = {}
exec(
    compile(ast.Module(body=[node], type_ignores=[]), "cab-table-original", "exec"),
    cab.__dict__,
    ns,
)
old = ns["_block_table"]
new = cab.CabReader._block_table
N = 65535
for checksum in [0, 1]:
    raw = (cab._DATA.pack(checksum, 1, 1) + b"x") * N

    def fresh():
        r = object.__new__(cab.CabReader)
        r._lock = threading.Lock()
        r._tables = {}
        r._folders = [SimpleNamespace(start=0, blocks=N)]
        r._data_reserve = 0
        r._source = SimpleNamespace(
            size=len(raw), read_exact=lambda p, n: raw[p : p + n]
        )
        r._max_meta = None
        r._table_bytes = 0
        return r

    out = {"old": [], "new": []}
    for i in range(15):
        for key, fn in (
            [("old", old), ("new", new)] if i % 2 else [("new", new), ("old", old)]
        ):
            r = fresh()
            gc.collect()
            gc.disable()
            start = time.process_time()
            t = fn(r, 0)
            out[key].append(time.process_time() - start)
            if key == "new":
                assert t.first_unchecked == (None if checksum else 0)
    print(
        json.dumps(
            {
                "checksum": checksum,
                "blocks": N,
                "median_ms": {k: statistics.median(v) * 1000 for k, v in out.items()},
                "table_size": sys.getsizeof(t),
                "index_size": sys.getsizeof(t.first_unchecked),
            }
        ),
        flush=True,
    )
