class Timeperiod:
    def __init__(self):
        self.start = self.end = 0

    def __init__(self, start: int, end: int):
        self.start = (start + 24000) % 24000
        self.end = (end + 24000) % 24000

    def __init__(self, time: int):
        self.start = self.end = (time + 24000) % 24000

    def contains(self, time: int) -> bool:
        return start <= end and time >= start and time <= end if start <= end else time <= end or time >= start

    def contains(self, t: 'Time') -> bool:
        return self.contains(t.get_ticks())

    def __str__(self):
        if self.start == self.end:
            return f"{Time().toString(self.start)}"
        return f"{Time().toString(self.start)}-{Time().toString(self.end)}"

    def __hash__(self) -> int:
        return hash((self.start, self.end))

    def __eq__(self, other: object):
        if not isinstance(other, Timeperiod):
            return False
        return self.end == other.end and self.start == other.start

class Time:
    @staticmethod
    def to_string(time: int) -> str:
        # Implement your time string conversion logic here
        pass
