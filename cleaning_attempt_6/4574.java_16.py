# No license information needed in Python!

from abc import ABC, abstractmethod

class AbstractComparableColumnDisplay(ABC):
    @abstractmethod
    def get_column_class(self) -> type(str):
        pass


class StringColumnDisplay(AbstractComparableColumnDisplay):
    def get_column_class(self) -> type(str):
        return str
