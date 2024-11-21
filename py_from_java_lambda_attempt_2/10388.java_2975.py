Here is the translation of the Java code to Python:
```
class IndexRange:
    def __init__(self, start: int, end: int):
        self.start = start
        self.end = end

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

    def __eq__(self, other):
        if not isinstance(other, IndexRange):
            return False
        return (other.start == self.start and other.end == self.end)

    def __hash__(self) -> int:
        return hash((self.start ^ (self.start >> 32)))
```
Note that I used Python's built-in `int` type for the start and end indices, since Java's `long` is equivalent to Python's `int`. Also, I replaced the getter/setter methods with Python's property decorator.