import re
from sqldark.tamper import Tamper, register
KW=["UNION","SELECT","FROM","WHERE","AND","OR","ORDER","GROUP","BY","LIMIT","HAVING","INTO","SLEEP","CONCAT","LIKE"]
@register
class HalfVersionedMoreKeywords(Tamper):
    name="halfversionedmorekeywords"
    description="MySQL<5.1: prepend /*!0 to each keyword"
    def tamper(self,p):
        for k in KW: p=re.sub(rf"\b{k}\b", f"/*!0{k}", p, flags=re.I)
        return p
