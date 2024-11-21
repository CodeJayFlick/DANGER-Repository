class LabelSearchAddressIterator:
    def __init__(self, label_iterator):
        self.label_iterator = label_iterator

    def has_next(self):
        return self.label_iterator.has_next()

    def next(self):
        symbol = self.label_iterator.next()
        return symbol.get_address()

    def remove(self):
        raise NotImplementedError("Remove operation not supported")

    def __iter__(self):
        return self
