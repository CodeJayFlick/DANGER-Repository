Here is the translation of the Java interface `PeekableIterator` to a Python class:

```python
class PeekableIterator:
    def __init__(self):
        pass

    def peek(self) -> object:
        raise NoSuchElementException("No next element available")

    def __iter__(self):
        return self

    def __next__(self) -> object:
        if not hasattr(self, 'current'):
            raise StopIteration
        current = getattr(self, 'current')
        delattr(self, 'current')
        return current


class NoSuchElementException(Exception):
    pass
```

Note that in Python, we don't have a direct equivalent to Java's interfaces. Instead, we can define a class with the desired methods and attributes. The `PeekableIterator` class has two main methods: `peek`, which returns the next element without advancing the iterator, and `__next__, which advances the iterator and returns the current element.

The `NoSuchElementException` is defined as an exception class to be raised when there are no more elements available in the iterator.