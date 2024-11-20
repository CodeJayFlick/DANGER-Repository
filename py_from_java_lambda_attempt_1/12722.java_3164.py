Here's the translation of the given Java interface into a Python class:

```Python
class IntPropertyMap:
    def __init__(self):
        self.properties = {}

    def add(self, addr: int, value: int) -> None:
        """Add an int value at the specified address."""
        self.properties[addr] = value

    def get_int(self, addr: int) -> int:
        """Get the integer value at the given address. Raises NoValueException if there is no property value at addr."""
        try:
            return self.properties[addr]
        except KeyError as e:
            raise ValueError("No value found for this address") from e
```

Note that Python does not have a direct equivalent to Java's interfaces, but we can achieve similar functionality using abstract base classes (ABCs) or simply by defining a class with methods. In this case, I chose the latter since it seems like `IntPropertyMap` is meant to be used as an interface for managing integer properties in some program.