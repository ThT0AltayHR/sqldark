from sqldark.tamper import Tamper, register
@register
class CharDoubleEncode(Tamper):
    name="chardoubleencode"
    description="Double URL-encode all characters (%2531 ...)"
    def tamper(self,p): return "".join("%25%02X"%ord(c) if False else "%25"+("%02X"%ord(c)) for c in p)
