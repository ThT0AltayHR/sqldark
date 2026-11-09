import re
from sqldark.tamper import Tamper, register
@register
class IfNull2CaseWhenIsNull(Tamper):
    name="ifnull2casewhenisnull"
    description="Replace IFNULL(A,B) with CASE WHEN ISNULL(A) THEN B ELSE A END"
    def tamper(self,p):
        return re.sub(r"IFNULL\(([^,]+),([^)]+)\)", r"CASE WHEN ISNULL(\1) THEN \2 ELSE \1 END", p, flags=re.I)
