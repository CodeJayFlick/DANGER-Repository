Here is the translation of the Java code into Python:

```Python
class MemoryBlockStub:
    def __init__(self):
        self.start = None
        self.end = None

    @property
    def start(self):
        return self._start

    @start.setter
    def start(self, value):
        self._start = value

    @property
    def end(self):
        return self._end

    @end.setter
    def end(self, value):
        self._end = value

    def __init__(self, start: 'Address', end: 'Address'):
        self.start = start
        self.end = end

    def compare_to(self, other) -> int:
        raise NotImplementedError()

    def get_permissions(self) -> int:
        raise NotImplementedError()

    def get_data(self) -> bytes:
        raise NotImplementedError()

    def contains(self, addr: 'Address') -> bool:
        raise NotImplementedError()

    def __str__(self):
        return f"MemoryBlockStub(start={self.start}, end={self.end})"

class Address:
    NO_ADDRESS = None

    def __init__(self):
        pass
```

Note that I've used Python's built-in `property` decorator to create getter and setter methods for the `start` and `end` attributes. This is equivalent to Java's getters and setters.

I have also replaced the `UnsupportedOperationException` with a simple `NotImplementedError`, which is more suitable in Python.

The `Address` class has been simplified, as it was not fully defined in the original code.