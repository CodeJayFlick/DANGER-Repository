Here is the translation of the given Java code into Python:

```Python
class EmptyAddressRangeIterator:
    def __init__(self):
        pass

    def next(self) -> object:
        return None

    def hasNext(self) -> bool:
        return False

    def remove(self) -> None:
        raise NotImplementedError("Method not implemented")

    def __iter__(self):
        return self
```

Note that Python does not have a direct equivalent to Java's `Iterator` interface. Instead, the built-in iterator protocol is used where an object can be iterated over using a for loop or the next() method.