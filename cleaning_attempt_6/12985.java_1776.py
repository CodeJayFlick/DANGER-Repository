class ReferenceIteratorTestStub:
    def __init__(self, refs):
        self.iterator = iter(refs)

    def remove(self):
        # do nothing for now
        pass

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self.iterator)
        except StopIteration:
            raise StopIteration()

    def has_next(self):
        try:
            next(self.iterator)
            return True
        except StopIteration:
            return False
