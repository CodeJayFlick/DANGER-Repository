Here is the translation of the Java interface `GTreeSelectionListener` to a Python abstract class:

```python
from abc import ABC, abstractmethod

class GTreeSelectionListener(ABC):
    @abstractmethod
    def value_changed(self, e):
        """Called whenever the value of the selection changes.
        
        :param e: The event that characterizes the change."""
```

Note that in Python, we don't have a direct equivalent to Java's `interface` keyword. Instead, we use abstract base classes (ABCs) from the `abc` module to define an interface-like construct.