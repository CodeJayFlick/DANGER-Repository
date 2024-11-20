Here is the translation of the given Java code into Python:

```Python
from abc import ABCMeta, abstractmethod

class BoundedShape(metaclass=ABCMeta):
    @abstractmethod
    def get_bounds(self) -> 'BoundedShape':
        pass

    @abstractmethod
    def description(self) -> str:
        pass
```

Note that in Python, we don't have a direct equivalent of Java's `interface` keyword. Instead, we use abstract base classes (ABCs). The `@abstractmethod` decorator is used to define methods that must be implemented by any subclass.