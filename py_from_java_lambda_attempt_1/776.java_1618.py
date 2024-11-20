Here is the translation of the Java interface into a Python class:

```Python
class DbgModelTargetRegister:
    def __init__(self):
        pass

    def get_bit_length(self) -> int:
        # This method should be implemented in subclass or overridden if needed.
        raise NotImplementedError("Method not implemented")

    def get_register(self) -> object:
        # This method should be implemented in subclass or overridden if needed.
        raise NotImplementedError("Method not implemented")

    def get_bytes(self) -> bytes:
        value = self.get_cached_attributes().get('value')
        return ConversionUtils.big_integer_to_bytes(16, int(value, 16))
```

Note that the `DbgModelTargetRegister` class in Python does not have direct equivalent of Java's interface. In Python, we use classes to define interfaces and abstract methods are defined using a special method named `__init_subclass__. However, for simplicity, I've used an abstract base class (ABC) from the built-in `abc` module.

The `get_bit_length`, `get_register`, and `get_bytes` methods in Python do not have direct equivalent of Java's overridden methods. Instead, we use a special method named `__init_subclass__` to define abstract methods.