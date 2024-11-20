Here is the translation of the given Java code into equivalent Python:

```Python
from abc import ABC, abstractmethod


class FieldKeyInteriorNode(ABC):
    @abstractmethod
    def key_changed(self, old_key: 'Field', new_key: 'Field', child_node) -> None:
        """Callback method for when a child node's leftmost key changes."""
```

Note that in Python, we don't have an exact equivalent of Java interfaces. Instead, we use abstract base classes (ABCs). The `@abstractmethod` decorator is used to define methods that must be implemented by any subclass.

The rest of the code doesn't translate directly into Python because it's not necessary for a simple interface definition like this one.