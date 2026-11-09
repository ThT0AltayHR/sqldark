"""Loader for the on-disk payload library (data/payloads/<dbms>/<technique>/*.json)."""
import json
import os

_BASE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "payloads")


def _iter_files(dbms=None, technique=None):
    if not os.path.isdir(_BASE):
        return
    dbms_dirs = [dbms] if dbms else sorted(
        d for d in os.listdir(_BASE) if os.path.isdir(os.path.join(_BASE, d)))
    for db in dbms_dirs:
        dbdir = os.path.join(_BASE, db)
        if not os.path.isdir(dbdir):
            continue
        techs = [technique] if technique else sorted(os.listdir(dbdir))
        for t in techs:
            tdir = os.path.join(dbdir, t)
            if not os.path.isdir(tdir):
                continue
            for fn in sorted(os.listdir(tdir)):
                if fn.endswith(".json"):
                    yield os.path.join(tdir, fn)


def load(dbms=None, technique=None):
    """Return a list of payload dicts, optionally filtered by dbms/technique."""
    out = []
    for path in _iter_files(dbms, technique):
        try:
            out.append(json.load(open(path, encoding="utf-8")))
        except Exception:
            continue
    return out


def count():
    return sum(1 for _ in _iter_files())


DBMS_ALIASES = {
    "mysql": "mysql", "MySQL": "mysql",
    "postgresql": "pgsql", "PostgreSQL": "pgsql", "pgsql": "pgsql",
    "microsoft sql server": "mssql", "Microsoft SQL Server": "mssql", "mssql": "mssql",
    "oracle": "oracle", "Oracle": "oracle",
    "sqlite": "sqlite", "SQLite": "sqlite",
}


def dbms_key(name):
    return DBMS_ALIASES.get(name, DBMS_ALIASES.get((name or "").lower(), None))
