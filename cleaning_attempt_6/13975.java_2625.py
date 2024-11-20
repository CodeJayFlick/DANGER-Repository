import datetime

class StoppingData:
    def __init__(self, when: datetime.datetime):
        self.when = when

    @property
    def when(self) -> datetime.datetime:
        return self._when

    @classmethod
    def of(cls, when: datetime.datetime) -> 'StoppingData':
        return cls(when)
