import random
from sqldark.tamper import Tamper, register
BLANKS=["%09","%0A","%0B","%0C","%0D","%A0"]
@register
class Space2MysqlBlank(Tamper):
    name="space2mysqlblank"
    description="MySQL: replace spaces with a random MySQL-allowed blank"
    def tamper(self,p): return "".join(random.choice(BLANKS) if c==" " else c for c in p)
