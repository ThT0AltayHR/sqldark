import re
from sqldark.tamper import Tamper, register
@register
class CommalessMid(Tamper):
    name="commalessmid"
    description="Replace MID(A,B,C) with MID(A FROM B FOR C)"
    def tamper(self,p):
        return re.sub(r"MID\(([^,]+),([^,]+),([^)]+)\)", r"MID(\1 FROM \2 FOR \3)", p, flags=re.I)
