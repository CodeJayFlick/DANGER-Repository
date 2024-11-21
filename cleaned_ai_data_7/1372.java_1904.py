from typing import TypeVar, Generic

class GdbEvent(Generic[T]):
    def __init__(self):
        pass

    def get_info(self) -> T:
        raise NotImplementedError("Subclasses must implement this method")

    def claim(self, cause: 'GdbPendingCommand[any]'):
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def cause(self) -> 'GdbCause':
        raise NotImplementedError("Subclasses must implement this property")

    def steal(self):
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def is_stolen(self) -> bool:
        raise NotImplementedError("Subclasses must implement this property")

    def new_state(self) -> 'GdbState' or None:
        raise NotImplementedError("Subclasses must implement this method")
