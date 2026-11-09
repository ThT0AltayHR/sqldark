"""End-to-end: dump-all + session save/resume + zip export via the CLI main()."""
import os, sys, threading, time, tempfile, glob, zipfile, json
os.environ["no_proxy"]="127.0.0.1,localhost"; os.environ["NO_PROXY"]="127.0.0.1,localhost"
sys.path.insert(0, os.path.dirname(__file__))
from http.server import HTTPServer
import vuln_app
from sqldark import cli

PORT=8914
threading.Thread(target=lambda: HTTPServer(("127.0.0.1",PORT), vuln_app.H).serve_forever(), daemon=True).start()
time.sleep(1)
work = tempfile.mkdtemp(); os.chdir(work)
url=f"http://127.0.0.1:{PORT}/product?id=1"
rc = cli.main(["-u",url,"--banner","--current-db","--dump-all",
               "--session","acme","--export","--no-color","--no-banner","-q"])
assert rc==0
sess = glob.glob(os.path.join(work,".sqldark/sessions/*.json"))
zips = glob.glob(os.path.join(work,".sqldark/database/*/*.zip"))
print("session file:", [os.path.basename(x) for x in sess])
print("zip file    :", [os.path.relpath(x,work) for x in zips])
d = json.load(open(sess[0]))
print("session dbms:", d["dbms"], "| tables:", list(d["databases"]["main"].keys()))
print("users rows  :", d["databases"]["main"]["users"]["rows"])
print("DELETE ->", cli.main(["--delete-session","acme","--no-color","--no-banner","-q"]))
print("remaining sessions:", glob.glob(os.path.join(work,".sqldark/sessions/*.json")))
print("ALL GOOD")
