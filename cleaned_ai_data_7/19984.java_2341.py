class CombinedIterator:
    def __init__(self, iterators):
        self.iterators = iterators
        self.removable = True
        self.current = None

    @property
    def removable(self):
        return self._removable

    @removable.setter
    def removable(self, value):
        if not isinstance(value, bool):
            raise TypeError("Removability must be a boolean")
        self._removable = value

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            try:
                iterable = next(self.iterators)
                iterator = iter(iterable)
                if not (iterator is None or not hasattr(iterator, 'has_next')):
                    break
            except StopIteration:
                return None
        self.current = iterator
        return next(self.current)

    def has_next(self):
        while True:
            try:
                iterable = next(self.iterators)
                iterator = iter(iterable)
                if not (iterator is None or not hasattr(iterator, 'has_next')):
                    break
            except StopIteration:
                return False
        self.current = iterator
        return bool(next(self.current))

    def remove(self):
        if not self.removable:
            raise UnsupportedOperationException()
        try:
            next(self.last)
            del next(self.last)
        except AttributeError as e:
            print(f"Error: {e}")
