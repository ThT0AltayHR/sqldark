from sqldark.tamper import Tamper, register
@register
class Space2Hash(Tamper):
    name = "space2hash"
    description = "MySQL: replace spaces with #comment + newline"
    def tamper(self, p): return p.replace(" ", "%23%0A")
