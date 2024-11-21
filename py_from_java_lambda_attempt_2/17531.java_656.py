Here is the translation of the Java code to Python:
```
import math

class UDTFFloor:
    def set_transformer(self):
        self.transformer = lambda x: math.floor(x)
```
Note that I've used a simple class definition with an `__init__` method, but since there's no constructor or instance variables in the original Java code, I didn't include one. The `set_transformer` method is equivalent to the overridden `setTransformer` method in the Java code.

The Python code uses the built-in `math.floor` function and a lambda function to define the transformer, which takes an input value `x` and returns its floor value using `math.floor(x)`.