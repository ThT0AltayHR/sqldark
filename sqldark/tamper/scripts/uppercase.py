from sqldark.tamper import Tamper, register
@register
class UpperCase(Tamper):
    name = "uppercase"
    description = "Uppercase the whole payload"
    def tamper(self, p): return p.upper()
