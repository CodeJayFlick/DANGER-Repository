Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Please note that Python does not have direct equivalent of Java's interfaces and abstract classes. However, we can achieve similar functionality using ABCMeta from the abc module for abstract methods and by defining a class within another function to mimic the static method in Java.