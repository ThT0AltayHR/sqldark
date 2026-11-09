import re
from sqldark.tamper import Tamper, register
@register
class Bluecoat(Tamper):
    name="bluecoat"
    description="Replace space after SQL statement with %09; = with LIKE (Bluecoat SG)"
    def tamper(self,p):
        p=re.sub(r"(?i)(SELECT|UNION|WHERE|AND|OR)\s", r"\1%09", p)
        return re.sub(r"\s*=\s*", " LIKE ", p)
