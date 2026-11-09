from sqldark.tamper import Tamper, register
@register
class CommentBeforeParentheses(Tamper):
    name="commentbeforeparentheses"
    description="Prepend an inline comment /**/ before each open parenthesis"
    def tamper(self,p): return p.replace("(", "/**/(")
