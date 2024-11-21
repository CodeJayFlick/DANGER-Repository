Here's your Java interface translated into equivalent Python classes:

```Python
from abc import ABC, abstractmethod
import enum
from typing import Set, Union

class TargetAttachKind(enum.Enum):
    BY_OBJECT_REF = 1
    BY_ID = 2


class TargetAttacher(ABC):
    @abstractmethod
    def get_supported_attach_kinds(self) -> set:
        pass

    @abstractmethod
    async def attach(self, target: 'TargetAttachable') -> None:
        pass

    @abstractmethod
    async def attach_by_id(self, pid: int) -> None:
        pass


class TargetAttacherImpl(TargetAttacher):
    _supported_attach_kinds = set()

    def get_supported_attach_kinds(self) -> set:
        return self._supported_attach_kinds

    async def attach(self, target: 'TargetAttachable') -> None:
        # implement your logic here
        pass

    async def attach_by_id(self, pid: int) -> None:
        # implement your logic here
        pass


class TargetAttachKindSet(ABC):
    @abstractmethod
    def __contains__(self, item: Union[TargetAttachKind, set]) -> bool:
        pass

    @abstractmethod
    def copy(self) -> 'TargetAttachKindSet':
        pass

    @classmethod
    def of(cls, *kinds: TargetAttachKind) -> 'TargetAttachKindSet':
        return cls(*kinds)

    @classmethod
    def empty_set(cls) -> 'TargetAttachKindSet':
        # implement your logic here
        pass


class ImmutableTargetAttachKindSet(TargetAttachKindSet):
    _set = set()

    def __init__(self, *kinds: TargetAttachKind):
        self._set.update(kinds)

    def copy(self) -> 'ImmutableTargetAttachKindSet':
        return ImmutableTargetAttachKindSet(*self._set)


class EmptyTargetAttachKindSet(TargetAttachKindSet):
    pass
```

Please note that Python does not have direct equivalent of Java's `CompletableFuture` and `enum`. The above code uses Python's built-in support for asynchronous programming (`async/await`) to simulate the behavior of `CompletableFuture`, and it defines an enum using Python's built-in `enum` module.