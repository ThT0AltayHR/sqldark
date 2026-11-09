from sqldark.tamper import Tamper, register
@register
class AppendNullByte(Tamper):
    name="appendnullbyte"
    description="Append an encoded NULL byte at the end of the payload"
    def tamper(self,p): return p + "%00"
