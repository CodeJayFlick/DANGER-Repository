from abc import ABCMeta, abstractmethod

class AbstractWithUndefinedDBTraceCodeUnitsMemoryView(metaclass=ABCMeta):
    def __init__(self, manager):
        super().__init__()
        self.manager = manager

    @abstractmethod
    def null_or_undefined(self, snap: int, address: str) -> object:
        pass

    @abstractmethod
    def empty_or_full_address_set_undefined(self, within: tuple) -> set:
        pass

    @abstractmethod
    def false_or_true_undefined(self) -> bool:
        pass

    def empty_or_full_iterable_undefined(self, snap: int, range: tuple, forward: bool = True):
        return (lambda: iter(
            AddressIterator(snap, address=range[0], direction='forward' if forward else 'backward')
        ))

class AddressIterator:
    def __init__(self, snap: int, address: str, direction: str):
        self.snap = snap
        self.address = address
        self.direction = direction

    def __iter__(self):
        return self

    def __next__(self):
        if self.direction == 'forward':
            self.address = next_address(self.address)
        else:
            self.address = previous_address(self.address)

        result = {'snap': self.snap, 'address': self.address}
        return result


class AddressSet(set):
    pass
