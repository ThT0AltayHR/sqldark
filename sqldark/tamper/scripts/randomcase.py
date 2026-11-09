import random
from sqldark.tamper import Tamper, register
@register
class RandomCase(Tamper):
    name = "randomcase"
    description = "Randomize the case of each character"
    def tamper(self, p):
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in p)
