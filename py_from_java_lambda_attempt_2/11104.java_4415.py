Here is the translation of the Java code to Python:
```
class Pair:
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
```
Note that I used the `@property` decorator to create getter and setter methods for the `start` and `end` attributes. This is a common pattern in Python to implement property-like behavior.

Also, I used type hints (`int`) for the method parameters and return types, which are optional but can be useful for documentation and static analysis purposes.