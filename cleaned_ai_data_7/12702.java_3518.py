class SymbolIteratorAdapter:
    def __init__(self, iterator):
        self.iterator = iterator

    def has_next(self):
        return next(self.iterator) if hasattr(self.iterator, 'has_next') else False

    def next_symbol(self):
        try:
            return next(self.iterator)
        except StopIteration:
            return None

    def remove(self):
        next(self.iterator)

    def __iter__(self):
        return self
