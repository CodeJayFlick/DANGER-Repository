Here is the translation of the given Java code into Python:

```Python
from abc import ABC, abstractmethod

class ColumnDisplay(ABC):
    @abstractmethod
    def get_column_value(self, row_object: 'AddressableRowObject') -> object:
        pass

    @abstractmethod
    def get_column_name(self) -> str:
        pass

    @abstractmethod
    def get_column_class(self) -> type:
        pass


class AddressableRowObject:
    pass
```

Note that in Python, we don't have a direct equivalent of Java's generics. However, the `AddressableRowObject` class is defined to represent an abstract row object.

The `ColumnDisplay` interface has been translated into a Python abstract base class (ABC) with three abstract methods: `get_column_value`, `get_column_name`, and `get_column_class`.