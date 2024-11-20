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
