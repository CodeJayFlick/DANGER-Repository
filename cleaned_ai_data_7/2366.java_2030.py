class AbstractSingleDBTraceCodeUnitsView(T):
    def __init__(self, space: 'DBTraceCodeSpace') -> None:
        super().__init__(space)

from typing import TypeVar
T = TypeVar('T', bound='DBTraceCodeUnitAdapter')

class DBTraceCodeSpace:
    pass

class AbstractBaseDBTraceCodeUnitsView(T):
    def __init__(self, space: 'DBTraceCodeSpace') -> None:
        super().__init__(space)

from typing import Generic
class AbstractSingleDBTraceCodeUnitsView(Generic[T]):
    def __init__(self, space: T) -> None:
        super().__init__(space)
