class FcgEdge:
    def __init__(self, start: 'FcgVertex', end: 'FcgVertex'):
        super().__init__(start, end)

    def clone_edge(self, start: 'FcgVertex', end: 'FcgVertex') -> 'FcgEdge':
        return FcgEdge(start, end)

    def is_direct_edge(self) -> bool:
        start_level = self.start.get_level()
        end_level = self.end.get_level()

        if start_level.is_source() or end_level.is_source():
            # all info leaving the source is important/'direct'
            return True

        parent = start_level.parent
        if parent == end_level:
            return True

        child = start_level.child
        return child == end_level
