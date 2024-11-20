class PeekableIterator:
    def __init__(self):
        pass

    def peek(self) -> object:
        raise NoSuchElementException("No next element available")

    def __iter__(self):
        return self

    def __next__(self) -> object:
        if not hasattr(self, 'current'):
            raise StopIteration
        current = getattr(self, 'current')
        delattr(self, 'current')
        return current


class NoSuchElementException(Exception):
    pass
