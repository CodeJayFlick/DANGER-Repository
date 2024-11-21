Here is the translation of the Java interface `IMultBatchReader` to a Python class:

```python
class IMultBatchReader:
    def __init__(self):
        pass

    def has_next_batch(self, full_path: str) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next_batch(self, full_path: str) -> 'BatchData':
        raise NotImplementedError("Subclasses must implement this method")
```

Note that in Python, we don't have a direct equivalent to Java's `interface` keyword. Instead, we define an abstract base class (ABC) using the `abc` module or by raising a `NotImplementedError`. In this case, I've chosen the latter.

The `has_next_batch` method takes a `full_path` string as input and returns a boolean indicating whether there is another batch available to read. The `next_batch` method also takes a `full_path` string as input and returns an instance of `BatchData`. Both methods raise a `NotImplementedError`, which means that any subclass implementing this interface must provide their own implementation for these methods.

The `BatchData` class is not defined in the original Java code, so I've left it as a placeholder. You would need to define your own Python equivalent of `BatchData` or use an existing library that provides similar functionality.