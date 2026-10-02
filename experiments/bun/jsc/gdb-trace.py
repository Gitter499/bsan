# gdb -x gdb-trace.py: print a short backtrace at each address in BREAKS (env GDB_BREAKS="0xaddr:label,...")
import gdb, os
gdb.execute("set pagination off"); gdb.execute("set print thread-events off"); gdb.execute("set debuginfod enabled off")
DEPTH = int(os.environ.get("GDB_DEPTH", "10"))
class B(gdb.Breakpoint):
    def __init__(self, spec, label):
        super().__init__(spec, internal=False); self.label = label
    def stop(self):
        try:
            boxp = int(gdb.parse_and_eval("*(unsigned long*)$rdi"))
        except Exception:
            boxp = 0
        print("=== %s box=0x%x" % (self.label, boxp))
        if os.environ.get("GDB_QUIET"): return False
        f = gdb.newest_frame(); i = 0
        while f is not None and i < DEPTH:
            try:
                sal = f.find_sal(); name = f.name() or "??"
                loc = f"{sal.symtab.filename}:{sal.line}" if sal and sal.symtab else ""
            except Exception as e:
                name, loc = "??", str(e)
            print(f"  #{i} {name[:160]} {loc}")
            try: f = f.older()
            except Exception: break
            i += 1
        return False
for item in os.environ["GDB_BREAKS"].split(","):
    addr, label = item.split(":")
    B("*" + addr, label)
gdb.execute("run")
try: gdb.execute("bt 30")
except Exception as e: print(e)
