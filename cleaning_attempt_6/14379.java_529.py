class AbstractFilter:
    def __init__(self):
        self.next = None

    def set_next(self, filter):
        self.next = filter

    def get_next(self):
        return self.next

    def get_last(self):
        last = self
        while last.get_next() is not None:
            last = last.get_next()
        return last

    def execute(self, order):
        if self.get_next():
            return self.get_next().execute(order)
        else:
            return ""
