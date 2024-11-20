from abc import ABC, abstractmethod
import threading


class DBTraceDelegatingManager(ABC):
    def __init__(self):
        self.read_lock = threading.Lock()
        self.write_lock = threading.Lock()

    @abstractmethod
    def check_is_in_memory(self, space: 'AddressSpace') -> None:
        pass

    def delegate_write(self, space: 'AddressSpace', func) -> object:
        self.check_is_in_memory(space)
        with self.read_lock:
            m = self.get_for_space(space, True)
            return func(m)

    def delegate_write_v(self, space: 'AddressSpace', func) -> None:
        self.check_is_in_memory(space)
        with self.write_lock:
            m = self.get_for_space(space, True)
            func(m)

    def delegate_write_i(self, space: 'AddressSpace', func) -> int:
        self.check_is_in_memory(space)
        with self.write_lock:
            m = self.get_for_space(space, True)
            return func(m)

    def delegate_write_all(self, spaces: Iterable['M'], func) -> None:
        with self.write_lock:
            for space in spaces:
                func(space)

    @abstractmethod
    def get_for_space(self, space: 'AddressSpace', create_if_absent: bool) -> object:
        pass

    # ... other methods ...

class AddressSpace:
    pass


def main():
    manager = DBTraceDelegatingManager()
    address_spaces = ['space1', 'space2']
    func = lambda x: print(x)
    manager.delegate_write_all(address_spaces, func)


if __name__ == "__main__":
    main()

