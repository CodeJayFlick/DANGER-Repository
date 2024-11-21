class TestEdge:
    def __init__(self, start: 'AbstractTestVertex', end: 'AbstractTestVertex'):
        super().__init__(start, end)

    def clone_edge(self) -> 'TestEdge':
        return self.__class__(self.start, self.end)
