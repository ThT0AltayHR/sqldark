from sqldark.tamper import Tamper, register
@register
class Space2Comment(Tamper):
    name = "space2comment"
    description = "Replace spaces with /**/ inline comments"
    def tamper(self, p): return p.replace(" ", "/**/")
