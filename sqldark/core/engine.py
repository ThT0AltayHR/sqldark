"""Orchestration: baseline, WAF fingerprint, per-point technique sweep."""
from sqldark.core.target import Target
from sqldark.waf.detector import WafDetector
from sqldark.dbms.errors import match_dbms
from sqldark.techniques.error_based import ErrorBased
from sqldark.techniques.boolean_blind import BooleanBlind
from sqldark.techniques.time_blind import TimeBlind
from sqldark.techniques.union_based import UnionBased
from sqldark.techniques.stacked_queries import StackedQueries
from sqldark.core.discovery import Discovery
from sqldark.enumeration.driver import run_enumeration
from sqldark.waf.tamper_advisor import recommend as recommend_tampers
from sqldark import tamper as _tamper_mod

TECHNIQUE_MAP = {
    "E": ErrorBased,
    "B": BooleanBlind,
    "U": UnionBased,
    "T": TimeBlind,
    "S": StackedQueries,
}
DEFAULT_ORDER = "EBUT"


class Engine:
    def __init__(self, http, log, techniques=DEFAULT_ORDER, skip_waf=False,
                 auto_tamper=False, level=1, risk=1):
        self.http = http
        self.log = log
        self.order = [c for c in techniques.upper() if c in TECHNIQUE_MAP]
        self.skip_waf = skip_waf
        self.auto_tamper = auto_tamper
        self.level = level
        self.risk = risk

    def scan(self, url, method="GET", data=None, enum_opts=None):
        target = Target(url, method=method, data=data)
        if not target.points:
            # No parameter in the URL: discover one, then retry on it.
            disc = Discovery(self.http, self.log)
            for cand in disc.find(url):
                res = self.scan(cand["url"], method=cand["method"],
                                data=cand["data"], enum_opts=enum_opts)
                if res:
                    return res
            self.log.error("no injectable parameters found after discovery")
            return []

        self.log.info(f"target has {len(target.points)} injection point(s)")

        # Baseline from the first point's original value
        first = target.points[0]
        base_url, base_data = first.build("")
        baseline = self.http.send(base_url, method=first.method, data=base_data)
        self._baseline = baseline
        self.log.info(f"baseline: HTTP {baseline.status}, "
                      f"{baseline.length} bytes, {baseline.elapsed:.2f}s")
        base_db = match_dbms(baseline.text)
        if base_db:
            self.log.warn(f"baseline page already shows a {base_db} error")

        if not self.skip_waf:
            waf = WafDetector(self.http, self.log).detect(first, baseline)
            if waf["detected"]:
                rec = recommend_tampers(waf.get("name"))
                if self.auto_tamper and not self.http.tampers and rec:
                    try:
                        chain = _tamper_mod.get(rec)
                        self.http.tampers = chain
                        self.log.warn("auto-tamper enabled for "
                                      f"{waf.get('name')}: " + " -> ".join(t.name for t in chain))
                    except Exception as ex:
                        self.log.warn(f"auto-tamper could not load chain: {ex}")
                elif waf.get("blocking") and rec:
                    self.log.warn("WAF is actively blocking; suggested: --tamper "
                                  + ",".join(rec))

        findings = []
        for point in target.points:
            self.log.info(f"testing parameter '{point.name}' ({point.place})")
            for letter in self.order:
                tech = TECHNIQUE_MAP[letter](self.http, self.log)
                tech.level = self.level
                tech.risk = self.risk
                res = tech.test(point, baseline)
                if res.vulnerable:
                    findings.append(res)
                    self.log.crit(
                        f"parameter '{point.name}' is INJECTABLE "
                        f"({res.technique}"
                        f"{', ' + res.dbms if res.dbms else ''})")
        self._summary(findings)
        self.last_enum = None
        if findings and enum_opts and any(enum_opts.get(k) for k in
                ("banner", "current_db", "tables", "columns", "dump", "dump_all")):
            self.last_enum = run_enumeration(self.http, self.log, findings,
                                             baseline, enum_opts)
        return findings

    def _summary(self, findings):
        self.log.info(f"total HTTP requests: {self.http.request_count}")
        if not findings:
            self.log.info("no SQL injection found with current settings")
            return
        dbms = next((f.dbms for f in findings if f.dbms), "unknown")
        self.log.ok(f"injectable: {len(findings)} vector(s), back-end DBMS: {dbms}")
