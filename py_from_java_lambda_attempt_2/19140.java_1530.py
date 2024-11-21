Here is the translation of the given Java code into equivalent Python:

```Python
from enum import Enum

class WithType:
    def __init__(self, type: 'Enum', value):
        self.type = type
        self.value = value

    @property
    def get_type(self) -> 'Enum':
        return self.type

    @property
    def get_value(self) -> object:
        return self.value

def of(type: Enum, value) -> 'WithType':
    return WithType(type, value)
```

Note that Python does not have a direct equivalent to Java's `@Value.Immutable` annotation or the `public interface` declaration. The above code defines a regular class in Python.

Also note that Python is dynamically typed and does not require explicit type declarations like Java does.