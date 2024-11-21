class Unchanged:
    def __init__(self, key):
        self.key = key

    @property
    def should_match_hash(self) -> bool:
        return True


def unchanged(key: 'Key') -> 'Unchanged':
    return Unchanged(key)


# Note that in Java, you would have used an interface to define the Operation and V types.
# In Python, we can use abstract base classes (ABCs) or duck typing instead.

from abc import ABC, abstractmethod

class Operation(ABC):
    @abstractmethod
    def should_match_hash(self) -> bool:
        pass


class ValueOperation(Operation):
    pass
