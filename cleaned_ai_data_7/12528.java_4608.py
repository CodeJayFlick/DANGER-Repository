from collections import Iterator

class CodeUnitIterator(Iterator):
    def __init__(self):
        self.has_next = False

    def hasNext(self) -> bool:
        return not self.has_next

    def next(self) -> object:
        if not self.hasNext():
            raise StopIteration
        else:
            # Add your logic here to get the next CodeUnit or null if no more CodeUnits.
            pass

EMPTY_ITERATOR = CodeUnitIterator()

class IterableCodeUnit(Iterator):
    def __init__(self, iterator: Iterator):
        self.iterator = iterator

    def hasNext(self) -> bool:
        return self.iterator.hasNext()

    def next(self) -> object:
        try:
            return self.iterator.next()
        except StopIteration:
            raise StopIteration
