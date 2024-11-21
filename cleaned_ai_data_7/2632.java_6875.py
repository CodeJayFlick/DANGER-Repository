class EmptyFunctionIterator:
    def __init__(self):
        self.has_next = False

    def hasNext(self) -> bool:
        return not self.has_next

    def next(self) -> object:
        return None

    def __iter__(self):
        return self


# Create an instance of the class
empty_iterator = EmptyFunctionIterator()
