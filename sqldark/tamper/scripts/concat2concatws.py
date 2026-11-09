import re
from sqldark.tamper import Tamper, register
@register
class Concat2ConcatWs(Tamper):
    name="concat2concatws"
    description="Replace CONCAT(a,b) with CONCAT_WS(0x20,a,b)"
    def tamper(self,p):
        return re.sub(r"CONCAT\(", "CONCAT_WS(0x20,", p, flags=re.I)
