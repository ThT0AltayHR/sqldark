import random
from sqldark.tamper import Tamper, register
BLANKS=["%01","%02","%03","%04","%05","%06","%07","%08","%09","%0A","%0B","%0C","%0D","%0E","%0F"]
@register
class Space2MssqlBlank(Tamper):
    name="space2mssqlblank"
    description="MSSQL: replace spaces with a random MSSQL-allowed blank"
    def tamper(self,p): return "".join(random.choice(BLANKS) if c==" " else c for c in p)
