class ImprovedIterator:
    def __init__(self, iter):
        self.iter = iter
        self.current = None

    def has_next(self):
        return self.iter.__iter__().__next__() is not None

    def next(self):
        if self.has_next():
            result = self.current = self.iter.__iter__().__next__()
            return result
        else:
            raise StopIteration

    def remove(self):
        self.iter.remove()

    @property
    def current(self):
        return self.current
