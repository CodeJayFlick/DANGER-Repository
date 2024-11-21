from abc import ABCMeta, abstractmethod

class WithHash(metaclass=ABCMeta):
    @abstractmethod
    def get_hash(self) -> int:
        pass

    @abstractmethod
    def getValue(self) -> object:
        pass


def with_hash(hash: int, value: object) -> 'WithHash':
    class ImmutableWithHash(WithHash):
        def __init__(self, hash: int, value: object):
            self._hash = hash
            self._value = value

        def get_hash(self) -> int:
            return self._hash

        def get_value(self) -> object:
            return self._value

    return ImmutableWithHash(hash, value)
