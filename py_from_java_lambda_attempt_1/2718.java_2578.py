Here is the translation of the given Java code into Python:

```Python
class Unique:
    @staticmethod
    def assert_one(col):
        if not col:
            raise AssertionError("Expected exactly one. Got none.")
        result = next(iter(col), None)
        try:
            next(iter(col))
            raise AssertionError("Expected exactly one. Got many.")
        except StopIteration:
            return result

    @staticmethod
    def assert_at_most_one(col):
        if not col:
            return None
        result = next(iter(col), None)
        try:
            next(iter(col))
            raise AssertionError("Expected at most one. Got many.")
        except StopIteration:
            return result
```

Please note that Python does not have a direct equivalent to Java's `Iterable` and `Iterator`. Instead, we use the built-in functions like `next()` and `iter()` which can be used with any iterable object in Python.