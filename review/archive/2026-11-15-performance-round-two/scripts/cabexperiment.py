import ast, subprocess, sys, inspect, textwrap, gc
import round2 as b
from archivey.internal.backends import cab_reader as cab

source = subprocess.check_output(
    [
        "git",
        "show",
        "529d7fbbeabafac2edf28ccb00afb8ea8af09053:src/archivey/internal/backends/cab_reader.py",
    ],
    text=True,
)
tree = ast.parse(source)
cls = next(
    n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "CabReader"
)
node = next(
    n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "open_member"
)
ns = {}
exec(
    compile(ast.Module(body=[node], type_ignores=[]), "cab-original", "exec"),
    cab.__dict__,
    ns,
)
OLD = ns["open_member"]
NEW = cab.CabReader.open_member


def patch(mode):
    cab.CabReader.open_member = OLD if mode == "old" else NEW


if __name__ == "__main__":
    patch(sys.argv[1])
    b.run("cab_read")
    gc.collect()
    gc.freeze()
    gc.disable()
    for _ in range(int(sys.argv[2])):
        b.run("cab_read")
