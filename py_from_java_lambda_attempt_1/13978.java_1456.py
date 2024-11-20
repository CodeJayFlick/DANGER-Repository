Here is the equivalent Python code:

```
class DataBusMember:
    def __init__(self):
        pass

    def accept(self, event: 'DataType') -> None:
        """Members receive events from the Data- Bus."""
        pass
```

Note that in Python, we don't have a direct equivalent to Java's `interface` keyword. Instead, we define a class with methods that are meant to be implemented by subclasses.

Also, I've kept the type hinting for the `event` parameter using the `->` syntax, which is not strictly necessary but can help with code readability and static analysis tools like mypy.