Here is the translation of the given Java code into Python:

```Python
class SubtractionExpression:
    def __init__(self, left_expression: 'Expression', right_expression: 'Expression'):
        super().__init__(left_expression, right_expression)

    def construct_transformer(self, left_parent_layer_point_reader: 'LayerPointReader', 
                               right_parent_layer_point_reader: 'LayerPointReader') -> 'ArithmeticBinaryTransformer':
        return ArithmeticSubtractionTransformer(left_parent_layer_point_reader, right_parent_layer_point_reader)

    def operator(self) -> str:
        return '-'
```

Note that Python does not have a direct equivalent to Java's `@Override` annotation. However, it is good practice in Python to include the comment `# noqa: E999` at the end of an overridden method if you are using a linter like flake8 or mypy, as they may otherwise flag this as an error.

Also note that I have used type hints for the function parameters and return types. These do not affect the runtime behavior of your code but can be useful when working with static analysis tools or IDEs that support Python type hinting.