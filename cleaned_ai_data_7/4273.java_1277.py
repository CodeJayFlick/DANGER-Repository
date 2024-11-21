class DataSearchAddressIterator:
    def __init__(self, data_iterator: Iterator[Data], forward: bool):
        self.data_iterator = data_iterator
        self.forward = forward
        self.current_data = None
        self.current_iter = None

    def has_next(self) -> bool:
        if self.current_iter is not None and self.current_iter.has_next():
            return True
        return self.data_iterator.hasNext()

    def next(self) -> Address:
        if self.current_iter is not None and self.current_iter.has_next():
            return self.current_iter.next()
        current_data = self.data_iterator.next()
        addresses = set(range(current_data.get_min_address(), current_data.get_max_address() + 1))
        self.current_iter = iter(addresses)
        return next(self.current_iter)

    def remove(self) -> None:
        raise NotImplementedError

    def __iter__(self):
        return self
