Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractProgramLocationTableColumn(ABC):
    def __init__(self, row_type: type, column_type: type):
        super().__init__()

    @abstractmethod
    def get(self) -> 'AbstractProgramLocationTableColumn':
        pass

from abc import ABC, abstractmethod