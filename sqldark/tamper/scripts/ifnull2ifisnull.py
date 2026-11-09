import re
from sqldark.tamper import Tamper, register
@register
class IfNull2IfIsNull(Tamper):
    name="ifnull2ifisnull"
    description="Replace IFNULL(A,B) with IF(ISNULL(A),B,A)"
    def tamper(self,p):
        return re.sub(r"IFNULL\(([^,]+),([^)]+)\)", r"IF(ISNULL(\1),\2,\1)", p, flags=re.I)
