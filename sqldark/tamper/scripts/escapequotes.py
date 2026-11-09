from sqldark.tamper import Tamper, register
@register
class EscapeQuotes(Tamper):
    name="escapequotes"
    description="Slash-escape single and double quotes"
    def tamper(self,p): return p.replace("'","\\'").replace('"','\\"')
