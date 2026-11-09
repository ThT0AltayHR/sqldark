from sqldark.tamper import Tamper, register
@register
class Space2Plus(Tamper):
    name = "space2plus"
    description = "Replace spaces with + signs"
    def tamper(self, p): return p.replace(" ", "+")
