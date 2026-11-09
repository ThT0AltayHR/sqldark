"""Audit regression: every CLI-exposed capability runs, --level/--risk take
effect, and the tool degrades gracefully on bad input. Local targets only."""
import os, sys, threading, time, json, tempfile
os.environ["no_proxy"] = "127.0.0.1,localhost"; os.environ["NO_PROXY"] = "127.0.0.1,localhost"
sys.path.insert(0, os.path.dirname(__file__))
from http.server import HTTPServer
import vuln_app
from sqldark.core.logger import Logger
from sqldark.core.http import HttpClient
from sqldark.core.engine import Engine
from sqldark.session.store import SessionStore
from sqldark import cli

PORT = 8971
threading.Thread(target=lambda: HTTPServer(("127.0.0.1", PORT), vuln_app.H).serve_forever(),
                 daemon=True).start()
time.sleep(1)
URL = f"http://127.0.0.1:{PORT}/product?id=1"
log = Logger(verbose=0, use_color=False)
fails = []

# 1) All five techniques run; E/B/U/T must detect at max level/risk.
http = HttpClient(log, timeout=20)
eng = Engine(http, log, techniques="EBUTS", level=5, risk=3)
found = eng.scan(URL)
techs = {f.technique for f in found}
for want in ["error-based", "boolean-based blind", "UNION query", "time-based blind"]:
    if want not in techs:
        fails.append(f"technique not detected at level5/risk3: {want}")
print("detected:", sorted(techs))

# 2) --risk actually changes behaviour. On a NON-injectable point the boolean
#    sweep runs to completion, so risk2 (adds OR-based conditions) must issue
#    strictly more attempts than risk1. Use a stub that never looks vulnerable.
from sqldark.techniques.boolean_blind import BooleanBlind
from sqldark.core.http import Response
class _StubHttp:
    def __init__(self): self.sent = 0; self.tampers = []
    def _tamper(self, p): return p
    def send(self, url, method="GET", data=None, raw_payload=None):
        self.sent += 1
        return Response(200, "same body", {}, 0.01, url)
class _StubPoint:
    name="id"; place="GET"; method="GET"
    def build(self, payload): return ("http://x/?id="+payload, None)
def sweep(risk):
    h=_StubHttp(); tech=BooleanBlind(h, log); tech.level=1; tech.risk=risk
    base=Response(200,"same body",{},0.01,"http://x/?id=1")
    tech.test(_StubPoint(), base)
    return h.sent
s1, s2 = sweep(1), sweep(2)
if not s2 > s1:
    fails.append(f"--risk had no effect on boolean attempts ({s1} vs {s2})")
print(f"boolean attempts risk1={s1} risk2={s2}")

# 3) Bad target degrades cleanly (no exception, empty findings)
try:
    h = HttpClient(log, timeout=3, retries=0)
    res = Engine(h, log).scan("http://127.0.0.1:1/x?id=1")
    if res:
        fails.append("unreachable target reported findings")
    print("bad-target handled, findings:", len(res))
except Exception as ex:
    fails.append(f"unreachable target raised: {ex!r}")

# 4) Corrupt session file -> load() returns None, not a crash
tmp = tempfile.mkdtemp()
st = SessionStore(base=tmp)
open(st._path("broken"), "w").write("{ not valid json ")
if st.load("broken") is not None:
    fails.append("corrupt session did not return None")
print("corrupt session load:", st.load("broken"))

# 5) CLI list commands exit 0
for argv in (["--list-tampers"], ["--list-sessions"], ["--version"]):
    try:
        rc = cli.main(argv)
        if argv == ["--version"]:
            pass  # argparse raises SystemExit(0)
        elif rc != 0:
            fails.append(f"cli {argv} returned {rc}")
    except SystemExit as e:
        if e.code not in (0, None):
            fails.append(f"cli {argv} SystemExit {e.code}")
print("cli list/version commands ok")

print("\n" + ("ALL GOOD" if not fails else "FAILURES:\n" + "\n".join(fails)))
sys.exit(1 if fails else 0)
