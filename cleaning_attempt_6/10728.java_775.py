class DefaultGEdge:
    def __init__(self, start, end):
        self.start = start
        self.end = end

    def get_start(self):
        return self.start

    def get_end(self):
        return self.end

    def __str__(self):
        return f"[{self.start}, {self.end}]"

    def __hash__(self):
        prime = 31
        result = 1
        if self.end is not None:
            result *= prime + hash(self.end)
        if self.start is not None:
            result *= prime + hash(self.start)
        return result

    def __eq__(self, other):
        if self is other:
            return True
        if other is None:
            return False
        if type(self) != type(other):
            return False

        other = DefaultGEdge(other.get_start(), other.get_end())
        return hash(self.start) == hash(other.start) and hash(self.end) == hash(other.end)
