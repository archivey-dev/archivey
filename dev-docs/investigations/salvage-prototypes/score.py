import json, sys, collections
R = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "/tmp/claude-0/sv/results.json"))
def norm(n):
    while n.startswith("./"): n = n[2:]
    return n.lstrip("/")
only = sys.argv[2].split(",") if len(sys.argv) > 2 else None
for fn in sorted(R):
    cases = R[fn]
    ref = {norm(n): h for n, h in cases["intact"]["random"]["ok"]}
    evs = sorted({e for c in cases.values() for e in c}) + ["union"]
    for c in cases.values():
        if "proto" in c and "random" in c:
            c["union"] = {"ok": c["random"].get("ok", []) + c["proto"].get("ok", [])}
    if only: evs = [e for e in evs if e in only]
    print(f"\n## {fn} ({len(ref)} files)")
    print("case".ljust(18) + "".join(e[:9].rjust(10) for e in evs))
    tot = collections.Counter()
    for c in sorted(cases):
        row = c[:17].ljust(18)
        for e in evs:
            r = cases[c].get(e)
            if r is None: row += "-".rjust(10); continue
            if "error" in r: row += "ERR".rjust(10); continue
            good = sum(1 for n, h in r.get("ok", []) if ref.get(norm(n)) == h)
            # dedupe
            good = len({norm(n) for n, h in r.get("ok", []) if ref.get(norm(n)) == h})
            tot[e] += good if c != "intact" else 0
            mark = "*" if r.get("open_error") else ""
            row += f"{mark}{good}".rjust(10)
        print(row)
    print("TOTAL".ljust(18) + "".join(str(tot[e]).rjust(10) for e in evs))
