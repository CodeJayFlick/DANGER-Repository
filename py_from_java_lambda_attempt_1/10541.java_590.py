Here is the translation of the Java interface `PropertyVisitor` to a Python abstract class:

```python
from abc import ABC, abstractmethod

class PropertyVisitor(ABC):
    @abstractmethod
    def visit_void(self): pass

    @abstractmethod
    def visit_string(self, value: str) -> None:
        ...

    @abstractmethod
    def visit_object(self, value: object) -> None:
        ...

    @abstractmethod
    def visit_saveable(self, value: 'Saveable') -> None:
        ...

    @abstractmethod
    def visit_int(self, value: int) -> None:
        ...
```

Note that in Python, we don't have a direct equivalent to Java's `interface` keyword. Instead, we use abstract base classes (ABCs) from the `abc` module to define an abstract class with abstract methods.

The `visit_void`, `visit_string`, `visit_object`, `visit_saveable`, and `visit_int` methods are defined as abstract using the `@abstractmethod` decorator. This means that any subclass of `PropertyVisitor` must implement these methods, but they can be left unimplemented in this base class itself.