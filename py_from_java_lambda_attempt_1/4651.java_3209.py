Here is the translation of the Java code to Python:
```
class DWARFBooleanAttribute:
    TRUE = DWARFBooleanAttribute(True)
    FALSE = DWARFBooleanAttribute(False)

    @classmethod
    def get(cls, b):
        return cls.TRUE if b else cls.FALSE

    def __init__(self, value: bool):
        self.value = value

    def get_value(self) -> bool:
        return self.value

    def __str__(self) -> str:
        return f"DWARFBooleanAttribute: {self.value}"
```
Note that I've used Python's `class` keyword to define a class, and the `@classmethod` decorator to create a class method. The rest of the code is similar in structure to the Java original, but with some minor differences due to Python's syntax and semantics.

In particular:

* In Python, we don't need explicit getters and setters like we do in Java; instead, we can simply use attribute access (e.g., `self.value`) to get or set the value.
* The `toString()` method is equivalent to Python's `__str__()` method, which returns a string representation of the object.