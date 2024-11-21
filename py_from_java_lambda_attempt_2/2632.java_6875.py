Here is the translation of the given Java code into equivalent Python:

```Python
class EmptyFunctionIterator:
    def __init__(self):
        self.has_next = False

    def hasNext(self) -> bool:
        return not self.has_next

    def next(self) -> object:
        return None

    def __iter__(self):
        return self


# Create an instance of the class
empty_iterator = EmptyFunctionIterator()
```

Note that Python does not have direct equivalent to Java's enum. The above code defines a regular class `EmptyFunctionIterator` with methods similar to those in the original Java code.