from sqldark.tamper import Tamper, register
@register
class CharUnicodeEncode(Tamper):
    name = "charunicodeencode"
    description = "Unicode-url-encode non-encoded characters (%u00XX)"
    def tamper(self, p):
        out = []
        for c in p:
            if c.isalnum() or c in "%":
                out.append(c)
            else:
                out.append("%%u%04X" % ord(c))
        return "".join(out)
