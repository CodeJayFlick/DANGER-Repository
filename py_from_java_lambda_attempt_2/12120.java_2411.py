Here is the translation of the given Java code into Python:

```Python
class EmptyRecordIterator:
    INSTANCE = None

    def __init__(self):
        self.INSTANCE = self

    def has_next(self) -> bool:
        return False

    def has_previous(self) -> bool:
        return False

    def next(self) -> object:
        return None

    def previous(self) -> object:
        return None

    def delete(self) -> bool:
        return False
```

Note that Python does not have a direct equivalent to Java's `throws IOException` syntax. Instead, you can use the `-> bool` or `-> None` syntax to indicate the function's return type and any exceptions it may raise.