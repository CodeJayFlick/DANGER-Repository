Here is the translation of the given Java code into equivalent Python:

```Python
import typing as t

TargetElementType = t.NamedTuple('TargetElementType', [
    ('index', str),
    ('type', type)
])

class TargetElementType:
    def __init__(self, index: str = "", type: type = type):
        self.index = index
        self.type = type
```

Note that Python does not have direct equivalents for Java's annotations (`@Target`, `@Retention`) or interfaces. The above code is a simple translation of the given Java interface into equivalent Python classes and tuples, which can be used to define custom types in your Python program.