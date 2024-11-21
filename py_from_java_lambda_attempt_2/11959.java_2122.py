Here is the translation of the Java interface `IntRangeMap` to a Python class:

```python
class IntRangeMap:
    def set_value(self, addresses: 'AddressSetView', value: int):
        pass  # implement this method in your subclass

    def set_value(self, start: 'Address', end: 'Address', value: int):
        pass  # implement this method in your subclass

    def get_value(self, address: 'Address') -> int:
        raise NotImplementedError("Method not implemented")

    @property
    def address_set(self) -> 'AddressSet':
        return None  # implement this property in your subclass

    @property
    def address_set(self, value: int) -> 'AddressSet':
        return None  # implement this property in your subclass

    def clear_value(self, addresses: 'AddressSetView'):
        pass  # implement this method in your subclass

    def clear_value(self, start: 'Address', end: 'Address'):
        pass  # implement this method in your subclass

    def clear_all(self):
        pass  # implement this method in your subclass

    def move_address_range(self, from_addr: 'Address', to_addr: 'Address', length: int, monitor) -> None:
        raise CancelledException("Operation cancelled")
```

Note that I've used type hints for the Python methods and properties. The `@property` decorator is used to define read-only properties in Python.

Also, since this code is an interface definition, you'll need to create a concrete subclass of `IntRangeMap` to implement its methods and properties.