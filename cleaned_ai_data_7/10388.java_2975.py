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
