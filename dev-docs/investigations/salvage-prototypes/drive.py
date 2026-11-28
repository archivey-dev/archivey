import json, os, sys, subprocess, concurrent.futures as cf
SV = "/tmp/claude-0/sv"; REPO = "/home/user/archivey"
TOOLS = {".zip": ["unzip", "7zz"], ".tar": ["tar", "7zz"], ".tar.gz": ["tar", "7zz"], ".tar.bz2": ["tar", "7zz"],
         ".tar.xz": ["tar", "7zz"], ".7z": ["7zz"], ".iso": ["7zz"], ".a": ["ar", "7zz"], ".rar": ["unrar", "7zz"]}
PY = os.path.join(REPO, ".venv/bin/python")
evaluators = sys.argv[1].split(",") if len(sys.argv) > 1 else ["random", "stream", "ref"]
def ext(fn): return fn[fn.index("."):]
def run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return json.loads(p.stdout.strip().splitlines()[-1])
    except Exception as e:
        return {"error": repr(e)[:200]}
jobs = []
for fn in sorted(os.listdir(f"{SV}/a")):
    cases = [("intact", f"{SV}/a/{fn}")] + [(c.rsplit(".",1)[0] if not c.endswith(ext(fn)) else c[: -len(ext(fn))], f"{SV}/d/{fn}/{c}") for c in sorted(os.listdir(f"{SV}/d/{fn}"))]
    for case, p in cases:
        for ev in evaluators:
            if ev in ("random", "stream"):
                jobs.append((fn, case, ev, [PY, f"{SV}/h/eval_archivey.py", p, ev]))
            elif ev == "ref":
                for t in TOOLS[ext(fn)]:
                    jobs.append((fn, case, t, [PY, f"{SV}/h/eval_ref.py", p, t]))
            elif ev == "proto":
                P = {".zip": "zipscan", ".tar": "tarscan", ".tar.gz": "gzresync", ".tar.bz2": "bz2blocks", ".tar.xz": "xzblocks",
                     ".7z": "7zlzma2", ".rar": "rarsearch", ".iso": "isotrees"}.get(ext(fn))
                if P: jobs.append((fn, case, "proto", [PY, f"{SV}/h/salvage_{P}.py", p]))
results = {}
with cf.ThreadPoolExecutor(8) as ex:
    futs = {ex.submit(run, j[3]): j for j in jobs}
    for f in cf.as_completed(futs):
        fn, case, ev, _ = futs[f]
        results.setdefault(fn, {}).setdefault(case, {})[ev] = f.result()
out = sys.argv[2] if len(sys.argv) > 2 else f"{SV}/results.json"
old = json.load(open(out)) if os.path.exists(out) else {}
for fn, cs in results.items():
    for c, evs in cs.items():
        old.setdefault(fn, {}).setdefault(c, {}).update(evs)
json.dump(old, open(out, "w"))
print(len(jobs), "jobs")
