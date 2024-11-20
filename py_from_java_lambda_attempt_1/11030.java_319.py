Here is the translation of the given Java code into equivalent Python:

```Python
from abc import ABC, abstractmethod

class ProjectDataColumn(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def is_default_column(self) -> bool:
        pass

    @abstractmethod
    def get_priority(self) -> int:
        pass

    def compare_to(self, other: 'ProjectDataColumn') -> int:
        return self.get_priority() - other.get_priority()
```

Note that Python does not have direct equivalent of Java's abstract classes and interfaces. However, we can achieve similar functionality using ABC (Abstract Base Classes) from the `abc` module in Python.

In this translation:

- The `ProjectDataColumn` class is defined as an Abstract Base Class.
- Two abstract methods are declared: `is_default_column` and `get_priority`. These must be implemented by any subclass of `ProjectDataColumn`.
- A method named `compare_to` is translated from Java's `compareTo` method. This method compares the priority of two instances of `ProjectDataColumn`, returning a negative integer if this column has lower priority, zero if they have equal priorities and positive if it has higher priority.
- The `@Override` annotation in Java does not exist in Python as decorators are used for similar purposes.

This translation maintains the same functionality as the original Java code.