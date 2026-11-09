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


_BOUNDARY_CACHE = None


def boundary_set(level=1):
    """Unique (prefix, suffix) boundaries drawn from the on-disk payload library.
    Higher --level exposes more of them, so the data files drive how wide the
    technique sweeps go instead of a hard-coded list."""
    global _BOUNDARY_CACHE
    if _BOUNDARY_CACHE is None:
        seen, out = set(), []
        for p in load():
            b = p.get("boundary") or {}
            key = (b.get("prefix", ""), b.get("suffix", ""))
            if key not in seen:
                seen.add(key)
                out.append(key)
        _BOUNDARY_CACHE = out
    # level 1 -> first 5, scaling up to the full set at level 5
    n = {1: 5, 2: 10, 3: 16, 4: 22, 5: len(_BOUNDARY_CACHE)}.get(level, 5)
    return _BOUNDARY_CACHE[:n]


def vectors_for(dbms_key_or_name, technique):
    """Raw vector strings from the library for a DBMS + technique."""
    k = dbms_key(dbms_key_or_name) or dbms_key_or_name
    return [p["vector"] for p in load(dbms=k, technique=technique)]
