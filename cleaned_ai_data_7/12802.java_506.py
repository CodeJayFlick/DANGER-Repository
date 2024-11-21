class ProgramChangeRecord:
    def __init__(self, type: int, start=None, end=None, affected_obj=None):
        self.start = start
        self.end = end
        self.affected_obj = affected_obj

    @property
    def start(self) -> 'Address':
        return self._start

    @start.setter
    def start(self, value: 'Address'):
        self._start = value

    @property
    def end(self) -> 'Address':
        return self._end

    @end.setter
    def end(self, value: 'Address'):
        self._end = value

    @property
    def affected_obj(self):
        return self._affected_obj

    @affected_obj.setter
    def affected_obj(self, value):
        self._affected_obj = value


class Address:
    pass  # You would need to implement the Address class in Python as well.
