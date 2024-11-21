Here is the translation of the Java interface `BasicFactory` to a Python class:

```python
class BasicFactory:
    def __init__(self):
        pass

    def create(self) -> object:
        """Creates an instance of T."""
        raise NotImplementedError("Subclasses must implement this method")

    def dispose(self, t: object) -> None:
        """Called when clients are finished with the given item and it should be disposed."""
        raise NotImplementedError("Subclasses must implement this method")
```

Note that in Python, we don't have a direct equivalent to Java's interfaces. Instead, we can use abstract base classes (ABCs) or protocols to define an interface. In this case, I've used the `NotImplementedError` exception to indicate that subclasses of `BasicFactory` must implement these methods.

Also, since Python is dynamically typed and doesn't have generics like Java does, I've omitted the type parameter `<T>` from the class definition.