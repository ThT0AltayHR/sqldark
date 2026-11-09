import re
from sqldark.tamper import Tamper, register
@register
class Percentage(Tamper):
    name="percentage"
    description="ASP: add a percent sign before each character (%S%E%L%E%C%T)"
    def tamper(self,p):
        return "".join("%"+c if c.isalnum() else c for c in p)
