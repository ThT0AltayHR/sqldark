from sqldark.tamper import Tamper, register
@register
class ApostropheNullEncode(Tamper):
    name = "apostrophenullencode"
    description = "Replace apostrophe with illegal double-unicode %00%27"
    def tamper(self, p): return p.replace("'", "%00%27")
