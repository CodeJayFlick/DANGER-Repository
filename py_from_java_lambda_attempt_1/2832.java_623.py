Here is the translation of the given Java interface into a Python class:

```Python
from enum import Enum

class QueryInclusion(Enum):
    ALL = 1
    SOME = 2
    NONE = 3


class Query:
    def __init__(self):
        pass

    def terminate_early_data(self, shape):
        # This method should be implemented in the subclass.
        raise NotImplementedError("Method 'terminateEarlyData' must be implemented.")

    def test_data(self, shape):
        # This method should be implemented in the subclass.
        raise NotImplementedError("Method 'testData' must be implemented.")

    def terminate_early_node(self, shape):
        # This method should be implemented in the subclass.
        raise NotImplementedError("Method 'terminateEarlyNode' must be implemented.")

    def test_node(self, shape):
        # This method should be implemented in the subclass.
        raise NotImplementedError("Method 'testNode' must be implemented.")

    def get_bounds_comparator(self):
        # This method should be implemented in the subclass.
        raise NotImplementedError("Method 'getBoundsComparator' must be implemented.")
```

This Python class is an abstract base class that provides a structure for any query. The methods `terminate_early_data`, `test_data`, `terminate_early_node`, `test_node` and `get_bounds_comparator` are declared but not defined, as they should be implemented in the subclass.