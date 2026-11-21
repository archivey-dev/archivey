"""Evaluate archivey on one (damaged) archive: which members list and read back intact."""
import json, sys, os, hashlib
import archivey

def norm(n):
    while n.startswith("./"): n = n[2:]
    return n.lstrip("/")

def run(path, streaming, salvage_kw):
    out = {"listed": [], "ok": [], "bad": {}, "open_error": None, "pass_error": None}
    kw = {}
    if salvage_kw: kw["salvage"] = True
    try:
        r = archivey.open_archive(path, streaming=streaming, **kw)
    except Exception as e:
        out["open_error"] = f"{type(e).__name__}: {e}"[:200]
        return out
    try:
        with r:
            it = r.stream_members()
            while True:
                try:
                    m, s = next(it)
                except StopIteration:
                    break
                except Exception as e:
                    out["pass_error"] = f"{type(e).__name__}: {e}"[:200]
                    break
                if not m.is_file:
                    continue
                name = norm(m.name)
                out["listed"].append(name)
                try:
                    data = s.read()
                    out["ok"].append([name, hashlib.sha1(data).hexdigest()])
                except Exception as e:
                    out["bad"][name] = f"{type(e).__name__}"
    except Exception as e:
        out["pass_error"] = out["pass_error"] or f"{type(e).__name__}: {e}"[:200]
    return out

if __name__ == "__main__":
    path, mode = sys.argv[1], sys.argv[2]
    print(json.dumps(run(path, mode == "stream", False)))
