class Delete:
    def __init__(self):
        pass

    @staticmethod
    def of(key: 'Key') -> 'Delete':
        return Delete(builder().key(key).build())

class Key:
    pass

class Operation:
    pass

from typing import TypeVar, Generic

V = TypeVar('V')

class ImmutableDelete(Generic[V], Delete):
    key: V

    @staticmethod
    def builder() -> 'ImmutableDelete.Builder':
        return ImmutableDelete.Builder()

    class Builder(ImmutableDelete):
        _key: Key

        def __init__(self) -> None:
            self._key = None  # type: Key

        def key(self, key: Key) -> 'Builder':
            self._key = key
            return self

        def build(self) -> ImmutableDelete:
            return ImmutableDelete(key=self._key)
