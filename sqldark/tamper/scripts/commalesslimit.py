import re
from sqldark.tamper import Tamper, register
@register
class CommalessLimit(Tamper):
    name="commalesslimit"
    description="Replace LIMIT M,N with LIMIT N OFFSET M (comma-less)"
    def tamper(self,p):
        return re.sub(r"LIMIT\s+(\d+),(\d+)", r"LIMIT \2 OFFSET \1", p, flags=re.I)
