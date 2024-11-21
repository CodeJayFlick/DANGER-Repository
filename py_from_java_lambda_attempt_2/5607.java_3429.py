Here is the translation of the Java interface `AddressPixelMap` to a Python class:
```python
class AddressPixelMap:
    def __init__(self):
        pass

    def create_mapping(self, width: int) -> None:
        """Create mapping with given width"""
        pass  # implementation left out for brevity

    def get_address(self, pixel: int) -> 'Address':
        """Get address corresponding to the given pixel"""
        raise NotImplementedError("Not implemented")

    def get_pixel(self, address: object) -> int:
        """Get pixel index corresponding to the given address"""
        raise NotImplementedError("Not implemented")

    def get_blocks(self) -> list['MemoryBlock']:
        """Get a list of memory blocks"""
        return []  # implementation left out for brevity

    def get_block_position(self, memory_block: 'MemoryBlock') -> tuple:
        """Get the position (x, y, width, height) of the given memory block"""
        raise NotImplementedError("Not implemented")

    def clear(self) -> None:
        """Clear any existing mapping or data"""
        pass  # implementation left out for brevity
```
Note that I've used Python's type hints to indicate the expected types of method parameters and return values. However, since this is an interface translation, some methods may not have a concrete implementation in Python (indicated by `raise NotImplementedError("Not implemented")`). You would need to implement these methods according to your specific use case.

Also, I've used the `object` type for the `address` parameter in `get_pixel`, as there isn't an equivalent concept of "Address" in Python. If you have a custom `Address` class or another way to represent addresses in Python, you would need to modify this code accordingly.