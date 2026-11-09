"""Self-contained live test: starts the vulnerable app in a background thread
and runs the full SQLDark engine against it. No external network needed."""
import os, sys, threading, time
os.environ["no_proxy"] = "127.0.0.1,localhost"
os.environ["NO_PROXY"] = "127.0.0.1,localhost"
sys.path.insert(0, os.path.dirname(__file__))

from http.server import HTTPServer
import vuln_app
from sqldark.core.logger import Logger
from sqldark.core.http import HttpClient
from sqldark.core.engine import Engine

PORT = 8911


def serve():
    HTTPServer(("127.0.0.1", PORT), vuln_app.H).serve_forever()


def main():
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    time.sleep(1)
    log = Logger(verbose=2, use_color=False)
    http = HttpClient(log)
    eng = Engine(http, log)
    opts = {"banner": True, "current_db": True, "tables": True,
            "columns": True, "dump": True, "max_rows": 50}
    findings = eng.scan(f"http://127.0.0.1:{PORT}/product?id=1", enum_opts=opts)

    techs = {f.technique for f in findings}
    print("\n=== ASSERTIONS ===")
    ok = True
    for need in ["error-based", "boolean-based blind", "UNION query", "time-based blind"]:
        hit = need in techs
        ok = ok and hit
        print(f"[{'PASS' if hit else 'FAIL'}] technique detected: {need}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
