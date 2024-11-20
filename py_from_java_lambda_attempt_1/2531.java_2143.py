Here is the translation of the Java interface `TraceDefinedDataRegisterView` into a Python class:

```python
class TraceDefinedDataRegisterView:
    def __init__(self):
        pass

    def create(self, lifespan: range, register: str, data_type: object) -> object:
        if not isinstance(register, str):
            raise ValueError("register must be a string")
        
        return self._create(lifespan, int.from_bytes(register.encode(), 'big'), data_type)

    def _create(self, lifespan: range, address: int, data_type: object, num_bytes: int) -> object:
        # Note that the equivalent of Java's CodeUnitInsertionException is not available in Python.
        # You may want to consider using a custom exception class or raising a built-in exception like ValueError
        return self._create_helper(lifespan, address, data_type)

    def _create_helper(self, lifespan: range, address: int, data_type: object) -> object:
        pass  # This method is not implemented in the original Java code. You may want to add your own implementation.
```

Note that Python does not have a direct equivalent of Java's `Range` class for representing a range of long values. Instead, we use the built-in `range` function which represents an interval of integers.

Also note that I've used the `_create_helper` method as a placeholder since it was not implemented in the original Java code. You may want to add your own implementation depending on what you're trying to achieve with this class.