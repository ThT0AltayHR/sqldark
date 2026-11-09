"""SQL injection techniques."""
import re
from difflib import SequenceMatcher

_DYNAMIC = re.compile(r"(?s)(<[^>]*csrf[^>]*>|name=[\"']?csrf[^>]*|\d{2}:\d{2}:\d{2}|"
                      r"[0-9a-f]{32}|viewstate[\"']?\s*value=[\"'][^\"']+)", re.I)


def normalize(text):
    """Strip highly dynamic content so comparisons are stable."""
    return _DYNAMIC.sub("", text or "")


def similarity(a, b):
    """Ratio 0..1 between two response bodies (length-aware + content)."""
    a, b = normalize(a), normalize(b)
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    # Fast length pre-check
    la, lb = len(a), len(b)
    if la and lb:
        ratio_len = min(la, lb) / max(la, lb)
        if ratio_len < 0.2:
            return ratio_len
    # Cap work for huge pages
    return SequenceMatcher(None, a[:20000], b[:20000]).ratio()


class Result:
    def __init__(self, technique, point, vulnerable=False, payload=None,
                 dbms=None, detail=None, confidence=0.0):
        self.technique = technique
        self.point = point
        self.vulnerable = vulnerable
        self.payload = payload
        self.dbms = dbms
        self.detail = detail
        self.confidence = confidence

    def __repr__(self):
        return (f"<Result {self.technique} {'VULN' if self.vulnerable else 'safe'} "
                f"{self.point.place}:{self.point.name}>")


class Technique:
    name = "base"
    letter = "?"

    def __init__(self, http, log):
        self.http = http
        self.log = log
        self.level = 1
        self.risk = 1

    def library_boundaries(self, fallback):
        """Boundaries from the on-disk payload library, scaled by --level.
        Falls back to the technique's own list if the library is unavailable."""
        try:
            from sqldark.core.payloads import boundary_set
            b = boundary_set(self.level)
            return b or fallback
        except Exception:
            return fallback

    def _send(self, point, payload):
        # Apply the tamper chain to the injected payload, then build the request.
        payload = self.http._tamper(payload)
        url, data = point.build(payload)
        return self.http.send(url, method=point.method, data=data)

    def test(self, point, baseline):
        raise NotImplementedError
