class FunctionSearchAddressIterator:
    def __init__(self, function_iterator):
        self.function_iterator = function_iterator

    def has_next(self):
        return self.function_iterator.has_next()

    def next(self):
        function = self.function_iterator.next()
        return function.get_entry_point()

    def remove(self):
        raise NotImplementedError("Remove operation not supported")

    def __iter__(self):
        return self
