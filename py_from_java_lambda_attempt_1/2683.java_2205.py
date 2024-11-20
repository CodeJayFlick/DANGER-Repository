Here is the translation of the Java interface `ExpanderArrowExpansionListener` to a Python abstract class:

```python
from abc import ABC, abstractmethod

class ExpanderArrowExpansionListener(ABC):
    @abstractmethod
    def changing(self, expanding: bool) -> None:
        pass  # Nothing

    @abstractmethod
    def changed(self, expanded: bool) -> None:
        pass
```

Note that in Python, we don't have a direct equivalent to Java's `interface` keyword. Instead, we use abstract base classes (ABCs) from the `abc` module to define an abstract class with abstract methods.

The `changing` method is marked as abstract using the `@abstractmethod` decorator, which means it must be implemented by any subclass that inherits from this abstract class. The same applies to the `changed` method.