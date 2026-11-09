import re
from sqldark.tamper import Tamper, register
@register
class Substring2LeftRight(Tamper):
    name="substring2leftright"
    description="Rewrite SUBSTRING(x,1,1) using LEFT/RIGHT where possible"
    def tamper(self,p):
        return re.sub(r"SUBSTRING\(([^,]+),1,1\)", r"LEFT(\1,1)", p, flags=re.I)
