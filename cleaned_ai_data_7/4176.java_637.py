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
