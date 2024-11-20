Here is the translation of the Java code to Python:
```
class EmptyMemReferenceIterator:
    def __init__(self):
        pass

    def hasNext(self) -> bool:
        # TODO
        return False

    def next(self) -> object:
        # TODO
        return None

    def remove(self) -> None:
        raise NotImplementedError("Cannot remove from an empty iterator")

    def __iter__(self) -> 'EmptyMemReferenceIterator':
        return self
```
Note that I've used Python's built-in `bool` type for the `hasNext()` method, and the `object` type for the `next()` method since it returns a generic object. The `remove()` method is implemented as raising an exception, as per Java's `UnsupportedOperationException`.