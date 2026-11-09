import re
from sqldark.tamper import Tamper, register
@register
class Between(Tamper):
    name = "between"
    description = "Replace > with NOT BETWEEN 0 AND, and = with BETWEEN x AND x"
    def tamper(self, p):
        p = re.sub(r"(\d+)\s*=\s*(\d+)", r"\1 BETWEEN \2 AND \2", p)
        return p
