Here's the translation of the Java code into Python:

```Python
class ExceptionBatchData:
    def __init__(self, exception):
        self.exception = exception

    def has_current(self):
        raise NotImplementedError("hasCurrent is not supported for ExceptionBatchData")

    def get_exception(self):
        return self.exception
```

Note that in the `has_current` method, I used Python's built-in `raise` statement to throw a `NotImplementedError`. This is equivalent to Java's `throw new UnsupportedOperationException()`.