Here is the translation of the Java interface into a Python class:

```Python
class GoToServiceListener:
    def __init__(self):
        pass

    def goto_completed(self, query_string: str, found_results: bool) -> None:
        """Notification that the GOTO completed."""
        pass  # implement your logic here

    def goto_failed(self, exc: Exception) -> None:
        """Notification that the GOTO failed with an exception."""
        pass  # implement your logic here
```

Note that in Python, we don't have a direct equivalent of Java's interface. Instead, we can define a class and use abstract methods to achieve similar functionality. The `__init__` method is added as it is not present in the original code but is required for classes in Python.