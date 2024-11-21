Here is the translation of the given Java interface into a Python class:

```Python
class OffsetReference:
    def __init__(self):
        pass

    def get_offset(self) -> int:
        """Returns the offset."""
        return 0  # Replace with actual implementation

    def get_base_address(self) -> 'Address':
        """Returns the base address."""
        return None  # Replace with actual implementation


class Address:  # This is a custom class, you would need to implement it
    pass
```

Please note that this translation assumes `get_offset` and `get_base_address` methods will be implemented in the derived classes. Also, Python does not have built-in support for interfaces like Java; instead, we use abstract base classes (ABCs) or protocols. In this case, I used a simple class as it seems to fit better with your requirements.

The custom `Address` class is also included here since you would need to implement its behavior in the actual code.