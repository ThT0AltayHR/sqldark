import random
from sqldark.tamper import Tamper, register
BLANKS = ["%09","%0A","%0C","%0D","%0B"]
@register
class Space2RandomBlank(Tamper):
    name = "space2randomblank"
    description = "Replace spaces with a random valid whitespace char (%09,%0A,...)"
    def tamper(self, p): return "".join(random.choice(BLANKS) if c==" " else c for c in p)
