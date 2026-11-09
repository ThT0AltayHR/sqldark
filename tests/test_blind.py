"""Force boolean-blind extraction (disable UNION) and verify a full dump."""
import os, sys, threading, time
os.environ["no_proxy"] = "127.0.0.1,localhost"; os.environ["NO_PROXY"]="127.0.0.1,localhost"
sys.path.insert(0, os.path.dirname(__file__))
from http.server import HTTPServer
import vuln_app
from sqldark.core.logger import Logger
from sqldark.core.http import HttpClient
from sqldark.core.engine import Engine

PORT = 8912
threading.Thread(target=lambda: HTTPServer(("127.0.0.1",PORT), vuln_app.H).serve_forever(), daemon=True).start()
time.sleep(1)
log = Logger(verbose=1, use_color=False)
http = HttpClient(log)
# technique B only -> extraction must use the blind oracle, char-by-char
eng = Engine(http, log, techniques="B")
opts = {"banner": True, "current_db": True, "tables": True, "columns": True, "dump": True, "max_rows":50}
f = eng.scan(f"http://127.0.0.1:{PORT}/product?id=1", enum_opts=opts)
print("\nrequests used:", http.request_count)
