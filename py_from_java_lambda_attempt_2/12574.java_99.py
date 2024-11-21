Here is the translation of the Java interface `RegisterChangeSet` to a Python class:

```python
class RegisterChangeSet:
    def __init__(self):
        self.change_set = set()

    def add_register_range(self, addr1: int, addr2: int) -> None:
        """Adds the ranges of addresses that have register changes."""
        for address in range(addr1, addr2 + 1):
            self.change_set.add(address)

    def get_register_address_set(self) -> set[int]:
        """Returns the set of Addresses containing register changes."""
        return self.change_set
```

Note:

* In Python, we don't have a direct equivalent to Java's `interface` keyword. Instead, we define a class with methods that are intended to be implemented by subclasses.
* The `addRegisterRange` method is translated to add the range of addresses to an internal set (`change_set`). This is not exactly equivalent to the original Java code, but it achieves similar functionality.
* The `getRegisterAddressSet` method simply returns the internal set.