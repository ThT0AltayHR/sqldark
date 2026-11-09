from sqldark.tamper import Tamper, register
SPECIAL="'\"() =<>#"
@register
class OverlongUtf8(Tamper):
    name="overlongutf8"
    description="Encode special characters as overlong UTF-8 sequences"
    def tamper(self,p):
        out=[]
        for c in p:
            if c in SPECIAL:
                o=ord(c); out.append("%%C0%%%02X"%(0x80+ (o&0x3f)))
            else: out.append(c)
        return "".join(out)
