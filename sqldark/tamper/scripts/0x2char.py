import re
from sqldark.tamper import Tamper, register
@register
class Hex2Char(Tamper):
    name="0x2char"
    description="MySQL: replace 0x hex literals with CHAR() sequences"
    def tamper(self,p):
        def conv(m):
            h=m.group(1)
            if len(h)%2: return m.group(0)
            try: bs=[int(h[i:i+2],16) for i in range(0,len(h),2)]
            except ValueError: return m.group(0)
            return "CHAR("+",".join(str(b) for b in bs)+")"
        return re.sub(r"0x([0-9A-Fa-f]+)", conv, p)
