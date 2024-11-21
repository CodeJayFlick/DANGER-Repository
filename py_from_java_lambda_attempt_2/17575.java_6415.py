Here is the translation of the Java code to Python:
```
class ArithmeticMultiplicationTransformer:
    def __init__(self, left_point_reader: 'LayerPointReader', right_point_reader: 'LayerPointReader'):
        super().__init__(left_point_reader, right_point_reader)

    def evaluate(self, left_operand: float, right_operand: float) -> float:
        return left_operand * right_operand
```
Note that I've used Python's type hints to indicate the types of the variables and method parameters. This is not strictly necessary for a simple class like this one, but it can be helpful for larger projects or when working with more complex codebases.

Also, keep in mind that Python does not have an exact equivalent to Java's `@Override` annotation. However, you could use a docstring comment to indicate that the method is overriding a parent class method:
```
    def evaluate(self, left_operand: float, right_operand: float) -> float:
        """Overrides superclass method"""
        return left_operand * right_operand
```