import json
import sys
from collections import defaultdict

rows = [json.loads(l) for f in sys.argv[1:] for l in open(f) if l.strip()]
groups = defaultdict(dict)
for r in rows:
    groups[(r["case"], r["depth"], r["read"])][r["strat"]] = r

bad = [r for r in rows if r["strat"] != "none" and not r["same"]]
print("mismatches:", len(bad))
for b in bad[:10]:
    print("  ", b)

CHILD = ("ppmd", "bzip3")
tot = defaultdict(lambda: defaultdict(float))
regret = defaultdict(lambda: defaultdict(float))
restarts = defaultdict(lambda: defaultdict(int))
for key, g in groups.items():
    base = g.get("none", {}).get("secs", 0.0)
    kind = "child" if key[0].startswith(CHILD) else "inproc"
    costs = {s: max(0.0, r["secs"] - base) for s, r in g.items() if s != "none"}
    if not costs:
        continue
    best = min(costs.values())
    for s, c in costs.items():
        tot[kind][s] += c
        regret[kind][s] = max(regret[kind][s], c - best)
        restarts[kind][s] += g[s]["restarts"]

for kind in tot:
    print(f"\n== {kind}: total extra seconds over all cases, worst loss vs best per case, restarts")
    for s, v in sorted(tot[kind].items(), key=lambda kv: kv[1]):
        print(f"  {s:14s} {v:8.3f}s  worst+{regret[kind][s]:.3f}s  restarts {restarts[kind][s]}")

if "-v" in sys.argv[0:1] or True:
    print("\n== per case (extra secs over no re-decode), T = prefix")
    strats = sorted({s for g in groups.values() for s in g if s != "none"})
    print(f"{'case':16s} {'depth':>8s} {'read':>8s}", " ".join(f"{s:>7s}" for s in strats))
    for key in sorted(groups):
        g = groups[key]
        base = g.get("none", {}).get("secs", 0.0)
        cells = []
        for s in strats:
            cells.append(f"{g[s]['secs'] - base:7.3f}" if s in g else "      -")
        print(f"{key[0]:16s} {key[1]:8d} {key[2]:8d}", " ".join(cells))
