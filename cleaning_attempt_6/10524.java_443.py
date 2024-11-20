class LongIterator:
    EMPTY = object()

    def __init__(self):
        pass

    def hasNext(self) -> bool:
        return False

    def next(self) -> int:
        return 0

    def hasPrevious(self) -> bool:
        return False

    def previous(self) -> int:
        return 0
