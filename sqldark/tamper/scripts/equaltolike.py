import re
from sqldark.tamper import Tamper, register
@register
class EqualToLike(Tamper):
    name = "equaltolike"
    description = "Replace = operator with LIKE"
    def tamper(self, p): return re.sub(r"\s*=\s*", " LIKE ", p)
