Here is the translation of the given Java interface into a Python class:

```Python
class ExternalReference:
    def __init__(self):
        pass

    def get_external_location(self) -> 'ExternalLocation':
        """Returns the object that represents the external location."""
        raise NotImplementedError("Method not implemented")

    def get_library_name(self) -> str:
        """Returns the name of the external library containing this location."""
        raise NotImplementedError("Method not implemented")

    def get_label(self) -> str | None:
        """Returns the external label associated with this location (may be null)."""
        raise NotImplementedError("Method not implemented")
```

Note that in Python, we don't have a direct equivalent of Java's `interface` keyword. Instead, we use abstract base classes (`ABC`) or regular classes to define interfaces. In this case, I've used an abstract class with all methods declared as abstract using the `@abstractmethod` decorator (which is not available in standard Python; it was introduced in Python 3.4).