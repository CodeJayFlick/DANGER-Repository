Here is the translation of the Java interface `Command` into a Python class:

```python
class Command:
    def __init__(self):
        pass

    def apply_to(self, obj: 'DomainObject') -> bool:
        """Applies the command to the given domain object."""
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def status_msg(self) -> str:
        """Returns the status message indicating the status of the command."""
        return None

    @property
    def name(self) -> str:
        """Returns the name of this command."""
        raise NotImplementedError("Subclasses must implement this method")
```

Note that I've used Python's type hints to indicate the types of the `obj` parameter and the return values, as well as the properties. This is not strictly necessary for a Python class, but it can be helpful for documentation purposes.

Also, since Java has an abstract keyword for interfaces with methods that must be implemented by subclasses, I've used Python's `NotImplementedError` to indicate that these methods are intended to be overridden in subclasses.