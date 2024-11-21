class DecoratingIterator:
    def __init__(self, from_iterator):
        self.from_iterator = from_iterator
        self.next = None

    def hasNext(self):
        if self.next is not None:
            return True
        else:
            self.next = self.compute_next()
            return self.next is not None

    def next(self):
        if self.next is None:
            return self.from_iterator.__next__()
        else:
            result = self.next
            self.next = None
            return result

    def compute_next(self):
        pass  # Implement your custom iteration logic here


class LazyFluentIterable(Iterator):
    def __init__(self, from_iterable):
        self.from_iterable = iter(from_iterable)
        self.decorating_iterator = DecoratingIterator(self.from_iterable)

    def __iter__(self):
        return self

    def __next__(self):
        if not self.decorating_iterator.hasNext():
            raise StopIteration
        else:
            return self.decorating_iterator.next()
