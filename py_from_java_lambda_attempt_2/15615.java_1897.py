Here is the translation of the Java interface `RepositoryFactory` to a Python class:

```python
class RepositoryFactory:
    def __init__(self):
        pass

    def create_repository(self, name: str, uri: str) -> dict:
        # This method should return a dictionary representing the repository instance.
        # For simplicity, we'll just return an empty dictionary for now.
        return {}

    def get_supported_schemes(self) -> set:
        # This method should return a set of URI schemes that this factory supports.
        # For simplicity, we'll just return a set containing 'http' and 'https'.
        return {'http', 'https'}
```

Note that in Python, we don't have an exact equivalent to Java's interfaces. Instead, we use abstract base classes (ABCs) or protocols to define the interface. In this case, I've used a regular class with methods that should be implemented by any subclass.

Also note that Python doesn't have built-in support for URI schemes like Java does. However, you can use libraries like `urllib.parse` or `pyuri` if needed.