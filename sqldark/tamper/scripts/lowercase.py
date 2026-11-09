from sqldark.tamper import Tamper, register
@register
class LowerCase(Tamper):
    name="lowercase"
    description="Lowercase the whole payload"
    def tamper(self,p): return p.lower()
