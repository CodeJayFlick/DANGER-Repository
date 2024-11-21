Here is the translation of the given Java interface into a Python class:

```Python
class IndexRangeIterator:
    def __init__(self):
        pass

    def has_next(self) -> bool:
        """Returns true if there are more index ranges."""
        return True  # This should be implemented based on your actual data structure.

    def next(self) -> 'IndexRange':
        """Returns the next index range."""
        raise NotImplementedError("Subclass must implement this method.")
```

Note that in Python, we don't have an exact equivalent of Java's interface. Instead, we can use abstract classes or interfaces from other libraries like `abc` (Abstract Base Classes). However, for simplicity and clarity, I've used a regular class here with placeholder methods. The actual implementation would depend on your specific requirements and data structure.