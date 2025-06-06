Here is the translation of the given Java code into Python:

```Python
class JSONToken:
    def __init__(self, type: str, start: int, end: int):
        self.type = type
        self.start = start
        self.end = end
        self.size = 0

    @property
    def type(self) -> str:
        return self._type

    @type.setter
    def type(self, value: str):
        self._type = value

    @property
    def start(self) -> int:
        return self._start

    @start.setter
    def start(self, value: int):
        self._start = value

    @property
    def end(self) -> int:
        return self._end

    @end.setter
    def end(self, value: int):
        self._end = value

    @property
    def size(self) -> int:
        return self._size

    @size.setter
    def size(self, value: int):
        self._size = value

    def inc_size(self):
        self.size += 1
```

Please note that Python does not have an exact equivalent of Java's `public` and `private` access modifiers. The `_type`, `_start`, `_end`, and `_size` attributes are intended to be private, but they can still be accessed directly from outside the class if needed.