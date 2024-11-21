Here is the translation of the Java code to Python:
```
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
```
Note that I've used Python's built-in `abstract` module to define the `FilterOperator` class as an abstract base class, and created separate exception classes for each of the exceptions mentioned in the Java code. The `IFilterOptimizer` interface is implemented using a simple abstract method definition.

Also note that I've kept the same variable names and structure as much as possible to make it easier to compare with the original Java code.