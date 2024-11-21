class NestedIterator:
    def __init__(self, outer: Iterator, inner_factory):
        self.outer = outer
        self.inner_factory = inner_factory
        self.inner = None
        self.prepped_inner = None

    @staticmethod
    def start(outer: Iterator, inner_factory) -> 'NestedIterator':
        return NestedIterator(outer, inner_factory)

    def prep_next_iterator(self):
        while True:
            if not self.outer.hasNext():
                break
            candidate = self.inner_factory.apply(next(self.outer))
            if candidate is not None and candidate.has_next():
                return candidate
        return None

    def hasNext(self) -> bool:
        if self.inner is not None and self.inner.has_next() or self.prepped_inner is not None and self.prepped_inner.has_next():
            return True
        self.prepped_inner = self.prep_next_iterator()
        return self.prepped_inner is not None

    def next(self):
        while True:
            if self.inner is None or not self.inner.has_next():
                if self.prepped_inner is None:
                    self.prepped_inner = self.prep_next_iterator()
                if self.prepped_inner is None:  # Still
                    return None
                self.inner, self.prepped_inner = self.prepped_inner, None
            return next(self.inner)

    def remove(self):
        raise NotImplementedError("remove() not implemented")
