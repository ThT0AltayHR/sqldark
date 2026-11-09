"""Error-based detection: provoke a DB error and read the DBMS signature."""
from sqldark.techniques import Technique, Result
from sqldark.dbms.errors import match_dbms

BOUNDARIES = ["'", "\"", "')", "\")", "`", "';", "\";", "\\", " AND 1=CONVERT(int,@@version)--"]


class ErrorBased(Technique):
    name = "error-based"
    letter = "E"

    def test(self, point, baseline):
        # Baseline must not already contain a DB error.
        base_db = match_dbms(baseline.text)
        for b in BOUNDARIES:
            resp = self._send(point, b)
            db = match_dbms(resp.text)
            if db and (not base_db):
                self.log.ok(f"error-based: {db} error triggered with payload {b!r}")
                return Result(self.name, point, vulnerable=True, payload=b,
                              dbms=db, detail=f"DB error signature for {db}",
                              confidence=0.95)
        return Result(self.name, point)
