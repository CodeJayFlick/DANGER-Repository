class MinusExpression:
    def __init__(self):
        pass

    def get_value(self, walker):
        val = self.get_unary().get_value(walker)
        return -val

    def to_string(self):
        return f"-({self.get_unary()})"


# Usage example:

class PatternExpression:
    def __init__(self):
        pass

    def get_value(self, walker):
        # implement your logic here
        pass


walker = ParserWalker()
pattern_expression = PatternExpression()

minus_expression = MinusExpression(pattern_expression)
print(minus_expression.get_value(walker))
