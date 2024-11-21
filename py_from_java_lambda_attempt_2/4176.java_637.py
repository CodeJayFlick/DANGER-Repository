Here is the translation of the Java code to Python:
```
class FREdge:
    def __init__(self, start: 'FRVertex', end: 'FRVertex'):
        self.start = start
        self.end = end

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

    def __str__(self):
        return f"{self.start} -> {self.end}"
```
Note that I've used Python's `@property` decorator to implement getter and setter methods for the `start` and `end` attributes. This is equivalent to Java's getters and setters, but with a more concise syntax.

Also, I've used Python's f-strings (introduced in Python 3.6) to format the string representation of the edge.