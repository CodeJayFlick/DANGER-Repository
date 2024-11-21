from abc import ABC, abstractmethod

class ColumnDisplay(ABC):
    @abstractmethod
    def get_column_value(self, row_object: 'AddressableRowObject') -> object:
        pass

    @abstractmethod
    def get_column_name(self) -> str:
        pass

    @abstractmethod
    def get_column_class(self) -> type:
        pass


class AddressableRowObject:
    pass
