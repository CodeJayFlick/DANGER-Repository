Here is the translation of the given Java code into equivalent Python:

```Python
class EmptyAddressIterator:
    def __init__(self):
        pass

    def next(self):
        return None

    def has_next(self):
        return False

    def remove(self):
        raise UnsupportedOperationException()

    def __iter__(self):
        return self


# Define an exception class for compatibility with Java's UnsupportedOperationException
class UnsupportedOperationException(Exception):
    pass
```

Note that Python does not have a direct equivalent to Java's `@Override` annotation. However, the method names and their implementations are identical in both languages, so it is clear which methods override or implement specific interfaces or classes.