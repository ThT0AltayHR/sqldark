import re
from sqldark.tamper import Tamper, register
@register
class MultipleSpaces(Tamper):
    name="multiplespaces"
    description="Add random multiple spaces around SQL keywords"
    def tamper(self,p):
        return re.sub(r"\s+", lambda m: " "*2, p)
