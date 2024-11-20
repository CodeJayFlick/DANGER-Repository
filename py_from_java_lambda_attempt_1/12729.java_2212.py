Here is the translation of the given Java interface into a Python class:

```Python
class SettingsPropertyMap:
    def add(self, addr: 'ghidra.program.model.address.Address', value: 'Settings'):
        pass  # Add an implementation for this method here.

    def get_settings(self, addr: 'ghidra.program.model.address.Address') -> 'Settings':
        return None  # Return the Settings object or null if property not found at addr.
```

Note that Python does not have a direct equivalent to Java's interface. Instead, we can use abstract base classes (ABCs) from the `abc` module in Python's standard library. Here is how you could define this class using ABC:

```Python
from abc import ABC, abstractmethod

class SettingsPropertyMap(ABC):
    @abstractmethod
    def add(self, addr: 'ghidra.program.model.address.Address', value: 'Settings'):
        pass  # Add an implementation for this method here.

    @abstractmethod
    def get_settings(self, addr: 'ghidra.program.model.address.Address') -> 'Settings':
        return None  # Return the Settings object or null if property not found at addr.
```

In Python, you would typically implement these methods in a subclass of `SettingsPropertyMap`.