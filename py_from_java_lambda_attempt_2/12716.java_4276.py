Here is the translation of the given Java code into Python:

```Python
class DefaultObjectPropertyMap:
    def __init__(self, name: str, object_class):
        self.prop_set = SaveableObjectPropertySet(name, object_class)

    def add(self, addr: int, value) -> None:
        if not isinstance(value, Saveable):
            raise TypeError("Value must be of type Saveable")
        self.prop_set.put_object(addr, value)

    def get_object(self, addr: int) -> any:
        return self.prop_set.get_object(addr)

    def get_object_class(self) -> type:
        return self.prop_set.get_object_class()
```

Note that Python does not have direct equivalent of Java's `Class` and `Saveable`. In this translation, I used Python's built-in types (`str`, `int`) for simplicity. Also, the concept of "Object" in Java is replaced with Python's generic type hinting using `any`.

Also note that Python has no direct equivalent to Java's exception handling mechanism. Instead, it uses try-except blocks and raises exceptions explicitly.

Here are some additional notes:

- The `Address` class from the original code was not translated as there is no direct equivalent in Python.
- In the translation of the constructor (`__init__` method), I used keyword arguments for simplicity.
- The type hints were added to make it clear what types each variable or parameter should be.