from datetime import datetime

class StartingData:
    def __init__(self, when):
        self.when = when

    @property
    def when(self):
        return self._when

    @classmethod
    def of(cls, when):
        return cls(when)
