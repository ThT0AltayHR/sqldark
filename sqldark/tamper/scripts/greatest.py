import re
from sqldark.tamper import Tamper, register
@register
class Greatest(Tamper):
    name="greatest"
    description="Replace > comparisons with GREATEST() (blind)"
    def tamper(self,p):
        return re.sub(r"(\w+)\s*>\s*(\w+)", r"GREATEST(\1,\2+1)=\1", p)
