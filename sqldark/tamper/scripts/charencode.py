from urllib.parse import quote
from sqldark.tamper import Tamper, register
@register
class CharEncode(Tamper):
    name = "charencode"
    description = "URL-encode all characters (percent encoding)"
    def tamper(self, p): return "".join("%%%02X" % ord(c) for c in p)
