Here is the translation of the Java interface `AccessContext` to a Python class:

```python
class AccessContext:
    def __init__(self):
        pass

    @property
    def operation_id(self) -> str:
        """Provide a unique id for the operation being validated (for correlation purposes)."""
        raise NotImplementedError("operation_id must be implemented")

    @property
    def user(self) -> 'Principal':
        """Provide the user identity."""
        raise NotImplementedError("user must be implemented")


class Principal:
    pass  # You would need to implement this class further based on your requirements.
```

Note that in Python, we don't have a direct equivalent of Java's `interface` keyword. Instead, we define an abstract base class (ABC) using the `abc` module or by defining a class with all methods declared as abstract (`raise NotImplementedError`). In this case, I've used the latter approach to mimic the Java interface.

The `Principal` class is also not implemented in Python code provided here, but you would need to implement it further based on your requirements.