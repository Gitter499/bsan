#!/usr/bin/env python3
"""run-unit.py <unit.json> <outdir> [extra rustc args...] — re-run one of bun's planned rustc units
standalone (inside the container) with extra flags, writing outputs to <outdir>. For memory experiments."""
import json, os, resource, subprocess, sys, time
m = json.load(open(sys.argv[1])); out = sys.argv[2]; extra = sys.argv[3:]
os.makedirs(out, exist_ok=True)
a = list(m['args'])
for i, x in enumerate(a):
    if x == '--out-dir': a[i+1] = out
    if x.startswith('--emit='): a[i] = '--emit=metadata,link'
env = dict(os.environ); env.update(m.get('env', {}))
cmd = [m['rustc']] + a + extra
t=time.time(); rc = subprocess.call(cmd, cwd=m['cwd'], env=env)
print(f"rc={rc} wall={time.time()-t:.0f}s maxrss={resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss//1024}MB", file=sys.stderr)
sys.exit(rc)
