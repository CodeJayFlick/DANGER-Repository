Here is the translation of the given Java code into equivalent Python:

```Python
from abc import ABCMeta, abstractmethod


class AbstractGColumnRenderer(metaclass=ABCMeta):
    """A convenience base class that combines GTableCellRenderer with GColumnRenderer interface."""
    
    @abstractmethod
    def __init__(self) -> None:
        pass

    # nothing yet; convenience interface
```

Note: Python does not have direct equivalent of Java's interfaces. Instead, we use abstract methods in a class to achieve similar functionality.