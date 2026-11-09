import re, random
from sqldark.tamper import Tamper, register
KW=["UNION","SELECT","FROM","WHERE","AND","OR"]
@register
class RandomComments(Tamper):
    name="randomcomments"
    description="Insert random inline comments inside keywords (SE/**/LECT)"
    def tamper(self,p):
        def frag(m):
            w=m.group(0); i=random.randint(1,len(w)-1); return w[:i]+"/**/"+w[i:]
        for k in KW: p=re.sub(rf"\b{k}\b", frag, p, flags=re.I)
        return p
