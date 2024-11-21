Here is the translation of the Java code to Python:
```
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
```
Note that I've used Python's type hinting system to indicate the types of variables and function parameters. This is not strictly necessary for a working program, but it can be helpful for documentation and static analysis tools.

Also, since there are no specific methods or attributes defined in the original Java code, this translation simply defines an abstract class with an `__init__` method that calls its parent's constructor.