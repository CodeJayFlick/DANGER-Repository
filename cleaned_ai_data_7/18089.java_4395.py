# Licensed under Apache License 2.0 (see NOTICE file)

class IFilterOptimizer:
    def optimize(self, filter: 'FilterOperator') -> 'FilterOperator':
        raise NotImplementedError("Subclasses must implement this method")

from abc import ABC, abstractmethod

class FilterOperator(ABC):
    @abstractmethod
    pass

class DNFOptimizeException(Exception): pass
class MergeFilterException(Exception): pass
class RemoveNotException(Exception): pass
