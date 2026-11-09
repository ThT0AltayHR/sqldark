import re
from sqldark.tamper import Tamper, register
KEYWORDS = ["UNION","SELECT","FROM","WHERE","AND","OR","ORDER","BY","GROUP","SLEEP"]
@register
class VersionedKeywords(Tamper):
    name = "versionedkeywords"
    description = "Wrap MySQL keywords in versioned comments /*!UNION*/"
    def tamper(self, p):
        for k in KEYWORDS:
            p = re.sub(rf"\b{k}\b", f"/*!{k}*/", p, flags=re.I)
        return p
