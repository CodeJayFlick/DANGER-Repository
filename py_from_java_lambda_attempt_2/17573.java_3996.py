Here is the translation of the Java code to Python:
```
class ArithmeticDivisionTransformer:
    def __init__(self, left_point_reader: 'LayerPointReader', right_point_reader: 'LayerPointReader'):
        super().__init__(left_point_reader, right_point_reader)

    def evaluate(self, left_operand: float, right_operand: float) -> float:
        return left_operand / right_operand
```
Note that I've used Python's type hints to indicate the types of the method parameters and return value. This is not strictly necessary for a simple translation like this, but it can help with code readability and maintainability.

Also, I've kept the same class name and method names as in the original Java code, since they seem reasonable and easy to understand.