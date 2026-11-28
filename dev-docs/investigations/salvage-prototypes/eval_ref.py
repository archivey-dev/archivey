"""Extract with the format's reference tool, report intact files by sha1."""
import json, sys, os, subprocess, tempfile, hashlib, shutil
path = os.path.abspath(sys.argv[1]); tool = sys.argv[2]
out = tempfile.mkdtemp(dir=os.environ.get("TMPX", "/tmp/claude-0/sv/tmp"))
cmds = {
 "unzip": ["unzip", "-o", "-qq", path, "-d", out],
 "7zz": ["7zz", "x", "-y", "-bd", "-bso0", "-bse0", f"-o{out}", path],
 "tar": ["tar", "-xf", path, "-C", out],
 "unrar": ["unrar", "x", "-y", "-idq", path, out + "/"],
 "ar": ["sh", "-c", f"cd {out} && ar x {path}"],
}
try:
    p = subprocess.run(cmds[tool], capture_output=True, timeout=60)
    rc = p.returncode
except subprocess.TimeoutExpired:
    rc = "timeout"
res = []
for dp, dn, fns in os.walk(out):
    for f in fns:
        fp = os.path.join(dp, f)
        if os.path.islink(fp): continue
        res.append([os.path.relpath(fp, out), hashlib.sha1(open(fp, "rb").read()).hexdigest()])
shutil.rmtree(out, ignore_errors=True)
print(json.dumps({"rc": rc, "ok": res}))
