Here is the translation of the Java interface `NumberRangeProducer` to a Python class:

```python
class NumberRangeProducer:
    def __init__(self):
        pass

    def get_lower_number(self) -> object:
        """Returns the lower range number; can be null"""
        return None  # or some other default value if needed

    def get_upper_number(self) -> object:
        """Returns the upper range number; can be null"""
        return None  # or some other default value if needed
```

Note that in Python, we don't have a direct equivalent to Java's `interface` keyword. Instead, we define a class with methods that are intended to be implemented by subclasses. In this case, the `NumberRangeProducer` class is an abstract base class (ABC) because it has no implementation and only defines two methods.

Also, Python doesn't have a built-in equivalent to Java's `@return` documentation comment. Instead, we can use docstrings or inline comments to provide documentation for our functions.