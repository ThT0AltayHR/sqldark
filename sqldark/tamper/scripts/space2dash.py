from sqldark.tamper import Tamper, register
@register
class Space2Dash(Tamper):
    name = "space2dash"
    description = "Replace spaces with a dash comment and newline (--%0A)"
    def tamper(self, p): return p.replace(" ", "--%0A")
