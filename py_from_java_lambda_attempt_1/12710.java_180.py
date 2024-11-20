Here is the translation of the Java interface `AddressSetPropertyMap` into a Python class:

```python
class AddressSetPropertyMap:
    def __init__(self):
        self.address_set = set()

    def add(self, start: int, end: int) -> None:
        """Add an address range to the property map."""
        for addr in range(start, end + 1):
            self.address_set.add(addr)

    def add(self, address_set_view: 'AddressSetView') -> None:
        """Add an address set to the property map."""
        self.address_set.update(address_set_view)

    def set(self, address_set_view: 'AddressSetView') -> None:
        """Clear and set the property map with a given address set."""
        self.clear()
        self.add(address_set_view)

    def remove(self, start: int, end: int) -> None:
        """Remove an address range from the property map."""
        for addr in range(start, end + 1):
            if addr in self.address_set:
                self.address_set.remove(addr)

    def remove(self, address_set_view: 'AddressSetView') -> None:
        """Remove an address set from the property map."""
        self.address_set.difference_update(address_set_view)

    def get_address_set(self) -> set:
        """Return the current address set for the property map."""
        return self.address_set.copy()

    def get_addresses(self) -> 'AddressIterator':
        """Return an iterator over all addresses in the property map."""
        # Implement this method
        pass

    def get_address_ranges(self) -> 'AddressRangeIterator':
        """Return an iterator over address ranges in the property map."""
        # Implement this method
        pass

    def clear(self) -> None:
        """Clear the property map."""
        self.address_set.clear()

    def contains(self, addr: int) -> bool:
        """Check if a given address is contained within the property map."""
        return addr in self.address_set


class AddressSetView(set):
    # Implement this class
    pass

# Implement these classes
class AddressIterator:
    pass

class AddressRangeIterator:
    pass
```

Note that I've used Python's built-in `set` data structure to represent the address set, and implemented methods for adding, removing, and checking membership in the set. The `AddressSetView`, `AddressIterator`, and `AddressRangeIterator` classes are not fully implemented as they were not provided in the original Java code.

Also note that Python does not have direct equivalents of Java's interfaces or abstract classes. Instead, I've used a class with no implementation (i.e., an "interface" in Python) to define the methods that must be implemented by any subclass.