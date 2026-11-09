from sqldark.tamper import Tamper, register
@register
class Space2MssqlHash(Tamper):
    name="space2mssqlhash"
    description="MSSQL: replace spaces with %23%0A"
    def tamper(self,p): return p.replace(" ","%23%0A")
