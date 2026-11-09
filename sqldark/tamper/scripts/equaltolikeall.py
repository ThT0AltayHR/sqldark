import re
from sqldark.tamper import Tamper, register
@register
class SymbolicLogical(Tamper):
    name="symboliclogical"
    description="Replace AND/OR with && and ||"
    def tamper(self,p):
        p=re.sub(r"\bAND\b"," %26%26 ",p,flags=re.I)
        return re.sub(r"\bOR\b"," %7C%7C ",p,flags=re.I)
