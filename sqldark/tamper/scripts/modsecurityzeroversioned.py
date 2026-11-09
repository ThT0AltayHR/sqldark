from sqldark.tamper import Tamper, register
@register
class ModSecurityZeroVersioned(Tamper):
    name="modsecurityzeroversioned"
    description="Embed the whole query in a zero-versioned comment /*!00000 ... */"
    def tamper(self,p): return f"/*!00000{p}*/"
