from abc import ABCMeta, abstractmethod

class DynamicColumnTableModel(metaclass=ABCMeta):
    @abstractmethod
    def get_column(self, index: int) -> 'DynamicTableColumn':
        """Returns the column for the given model index"""
        
    @abstractmethod
    def get_column_index(self, column: 'DynamicTableColumn') -> int:
        """Returns the model index for the given column"""

class DynamicTableColumn(metaclass=ABCMeta):
    @abstractmethod
    pass

# You can define your own classes that implement these interfaces if needed.
