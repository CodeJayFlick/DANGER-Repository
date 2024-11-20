Here is the translation of the given Java code into Python:

```Python
class PlusExpression:
    def __init__(self, left_expression, right_expression):
        self.left_expression = left_expression
        self.right_expression = right_expression

    def interpret(self):
        return self.left_expression.interpret() + self.right_expression.interpret()

    def __str__(self):
        return "+"
```

Note that Python does not have a direct equivalent to Java's `package` statement. In Python, you can organize your code into modules and packages using the standard library module `__init__.py`.