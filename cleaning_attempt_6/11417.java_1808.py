class AssemblyResolutionResults:
    def __init__(self):
        self.resolutions = set()

    @classmethod
    def singleton(cls, rc):
        return cls({rc})

    def add(self, ar):
        return ar in self.resolutions.add(ar)

    def absorb(self, that):
        self.resolutions.update(that.resolutions)

    def add_all(self, c):
        return self.resolutions.update(c)

    @property
    def resolutions(self):
        return frozenset(self.resolutions)
