class PropertySetIndexRangeIterator:
    def __init__(self, set: dict, start: int) -> None:
        self.long_it = iter(set.keys())  # equivalent to getPropertyIterator
        if next(self.long_it, None):  # hasNext()
            self.index_range = IndexRange(start, next(self.long_it) - 1)
        else:
            self.index_range = IndexRange(start, float('inf'))  # equivalent to Long.MAX_VALUE

    def hasNext(self) -> bool:
        return self.index_range is not None

    def next(self) -> tuple[int, int]:
        temp = self.index_range
        self.get_next_index_range()
        return temp

    def get_next_index_range(self) -> None:
        if self.index_range is None:  # equivalent to indexRange == null
            return
        old_end = self.index_range.end
        if old_end == float('inf'):  # equivalent to Long.MAX_VALUE
            self.index_range = None
            return
        if next(self.long_it, None):  # hasNext()
            self.index_range = IndexRange(old_end + 1, next(self.long_it) - 1)
            return
        self.index_range = IndexRange(old_end + 1, float('inf'))

class IndexRange:
    def __init__(self, start: int, end: int) -> None:
        self.start = start
        self.end = end

    @property
    def get_start(self) -> int:
        return self.start

    @property
    def get_end(self) -> int:
        return self.end
