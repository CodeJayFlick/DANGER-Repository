Here is the translation of the given Java code into equivalent Python:

```Python
class PrimitiveField:
    def __init__(self):
        self._is_null = False

    @property
    def is_null(self):
        return self._is_null

    def set_null(self):
        if not hasattr(self, '_immutable'):
            self._is_null = True

    def updating_primitive_value(self):
        if not hasattr(self, '_immutable'):
            self._is_null = False

    def __str__(self):
        null_state = ""
        if self.is_null:
            null_state = "(NULL)"
        return f"{type(self).__name__}{null_state}: {self.get_value_as_string()}"

class Field:
    pass
```

Please note that Python does not have a direct equivalent to Java's abstract classes. However, we can achieve similar functionality using inheritance and polymorphism in Python.

Also, the `checkImmutable()` method is removed as it seems like an internal check for immutability which doesn't seem relevant here.