Here is the translation of the Java code to Python:
```
import abc

class MeasurementCollector(metaclass=abc.ABCMeta):
    def __init__(self, start_node: 'IMNode', path: 'PartialPath') -> None:
        super().__init__(start_node, path)
        self.is_measurement_traverser = True  # equivalent to isMeasurementTraverser in Java

    @abstractmethod
    def process_internal_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        return False

    @abstractmethod
    def process_full_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        if not node.is_measurement():
            return False
        self.collect_measurement(node.as_measurement_mnode())
        return True

    def collect_measurement(self, node: 'IMeasurementMNode') -> None:
        pass  # abstract method implementation left to subclass
```
Note that I used the `abc` module from Python's standard library to define an abstract base class (ABC). This allows us to use abstract methods and properties in our translation.

Also, I replaced Java-specific constructs like package declarations, import statements, and some syntax with their equivalent Python counterparts.