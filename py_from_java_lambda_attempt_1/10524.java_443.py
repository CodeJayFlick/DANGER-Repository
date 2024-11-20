Here is the translation of the Java interface into a Python class:

```Python
class LongIterator:
    EMPTY = object()

    def __init__(self):
        pass

    def hasNext(self) -> bool:
        return False

    def next(self) -> int:
        return 0

    def hasPrevious(self) -> bool:
        return False

    def previous(self) -> int:
        return 0
```

Note that Python does not have a direct equivalent to Java's interfaces. Instead, we can use abstract classes or protocols (in the context of type hints). In this case, I chose to implement an abstract class with all methods as placeholders for any actual implementation.