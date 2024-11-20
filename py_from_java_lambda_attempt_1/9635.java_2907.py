Here is the translation of the given Java code into Python:

```Python
class FilterListener:
    def __init__(self):
        pass

    def filter_changed(self, text: str) -> None:
        """An interface that will be called when the text filter changes."""
        # Your implementation here
```

Note that in Python, we don't have a direct equivalent of Java's `interface` keyword. Instead, we define a class with methods that must be implemented by any subclass or instance. The `filter_changed` method is defined to take one argument (`text`) and return `None`.