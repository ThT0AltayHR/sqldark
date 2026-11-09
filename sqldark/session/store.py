"""Save, resume, list, and delete scan sessions ("sezon").

A session is a named snapshot of everything SQLDark has learned about a target:
the injection vectors it confirmed, the detected DBMS/WAF, and any enumerated
schema and dumped rows. Sessions live under <base>/sessions/<name>.json so a
scan can be paused and resumed instead of re-run from scratch."""
import json
import os
import time

def _default_base():
    return os.path.join(os.getcwd(), ".sqldark")


class SessionStore:
    def __init__(self, base=None):
        self.base = base or _default_base()
        self.dir = os.path.join(self.base, "sessions")
        os.makedirs(self.dir, exist_ok=True)

    def _path(self, name):
        safe = "".join(c for c in name if c.isalnum() or c in "-_.") or "session"
        return os.path.join(self.dir, safe + ".json")

    def save(self, name, data):
        data = dict(data or {})
        data["_saved_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        data["_name"] = name
        with open(self._path(name), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return self._path(name)

    def load(self, name):
        path = self._path(name)
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def list(self):
        out = []
        for fn in sorted(os.listdir(self.dir)):
            if fn.endswith(".json"):
                try:
                    d = json.load(open(os.path.join(self.dir, fn), encoding="utf-8"))
                except Exception:
                    d = {}
                out.append({
                    "name": d.get("_name", fn[:-5]),
                    "saved_at": d.get("_saved_at", "?"),
                    "target": d.get("target", "?"),
                    "dbms": d.get("dbms", "?"),
                })
        return out

    def delete(self, name):
        path = self._path(name)
        if os.path.exists(path):
            os.remove(path)
            return True
        return False
