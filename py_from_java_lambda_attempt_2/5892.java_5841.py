Here is the translation of the Java code to Python:
```
class SequenceRange:
    def __init__(self, start: 'SequenceNumber', end: 'SequenceNumber'):
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

    def __eq__(self, other):
        if not isinstance(other, SequenceRange):
            return False
        return self.start == other.start and self.end == other.end

    def __hash__(self):
        return hash(self.start)

    def __str__(self):
        return f"{self.start}-{self.end}"

    def contains(self, seq: 'SequenceNumber'):
        addr = seq.target
        index = seq.time
        start_addr = self.start.target
        start_index = self.start.time
        end_addr = self.end.target
        end_index = self.end.time

        c = addr.compare_to(start_addr)
        if c == 0:
            c = index - start_index
        if c < 0:
            return False

        c = addr.compare_to(end_addr)
        if c == 0:
            c = index - end_index
        return c <= 0


class SequenceNumber:
    def __init__(self, target: 'Address', time: int):
        self.target = target
        self.time = time

    @property
    def target(self):
        return self._target

    @target.setter
    def target(self, value):
        self._target = value

    @property
    def time(self):
        return self._time

    @time.setter
    def time(self, value):
        self._time = value


class Address:
    def __init__(self):
        pass  # assume this is implemented elsewhere

    def compare_to(self, other: 'Address'):
        raise NotImplementedError("compare_to not implemented")
```
Note that I had to create a `SequenceNumber` class and an `Address` class in Python, as they were not provided in the original Java code. The `Address` class has been left incomplete, assuming it will be implemented elsewhere.

Also, note that I used type hints for the method parameters and return types, but this is optional and can be removed if desired.