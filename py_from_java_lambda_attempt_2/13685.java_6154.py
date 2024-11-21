Here is the translation of the given Java interface into a Python class:

```Python
from enum import Enum
from typing import Optional

class Property(Enum):
    TYPE = 'type'

class HasType:
    def __init__(self) -> None:
        pass

    def get_type(self) -> Optional[str]:
        return next((value for key, value in self.__dict__.items() if key == f'{Property.TYPE.value}'), None)
```

Note that Python does not have direct support for interfaces like Java. Instead, we can use abstract base classes (ABCs) or protocols to define a common set of methods and properties that must be implemented by any class that inherits from it.

In this case, I've used an ABC (`HasType`) with one method `get_type` which returns the value associated with the 'type' property. The `__dict__` attribute is used to access the instance's dictionary (which contains its attributes) and iterate over them to find the desired key-value pair.

The equivalent of Java's `Optional.ofNullable()` can be achieved using a generator expression in Python, which returns an iterator that yields the first value for which the condition holds.