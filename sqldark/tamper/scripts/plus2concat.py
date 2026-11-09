from sqldark.tamper import Tamper, register
@register
class Plus2Concat(Tamper):
    name="plus2concat"
    description="MSSQL: replace + string concatenation with explicit spacing"
    def tamper(self,p): return p.replace("+", "%2B")
