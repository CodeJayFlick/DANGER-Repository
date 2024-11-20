Here is the translation of the given Java code into Python:

```Python
class MinusExpression:
    def __init__(self, left_expression: 'Expression', right_expression: 'Expression'):
        self.left_expression = left_expression
        self.right_expression = right_expression

    def interpret(self):
        return self.left_expression.interpret() - self.right_expression.interpret()

    def __str__(self):
        return "-"


class Expression:
    pass


# Example usage:

expression1 = MinusExpression(Expression(), Expression())
print(expression1.interpret())  # Output: ? (depending on the implementation of Expression class)
```

Please note that in Python, we don't have a direct equivalent to Java's `package` statement. The code above is written as if it were part of a larger package or module.

Also, I've used type hints for clarity and readability purposes only. They do not affect how the code runs.