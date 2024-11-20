class PlusExpression:
    def __init__(self, left_expression, right_expression):
        self.left_expression = left_expression
        self.right_expression = right_expression

    def interpret(self):
        return self.left_expression.interpret() + self.right_expression.interpret()

    def __str__(self):
        return "+"
