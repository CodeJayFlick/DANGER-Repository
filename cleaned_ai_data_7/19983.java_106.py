import itertools

class CheckedIterator:
    def __init__(self, iter, checker):
        self.iter = iter
        self.checker = checker
        self.returned_next = True
        self.next = None

    def hasNext(self):
        if not self.returned_next:
            return True
        while self.iter.hasNext():
            self.next = next(self.iter)
            if self.checker.check(self.next):
                self.returned_next = False
                return True
        return False

    def __next__(self):
        if not self.hasNext():
            raise StopIteration
        self.returned_next = True
        return self.next

    def remove(self):
        self.iter.remove()
