Here is the translation of the Java code to Python:
```
import io

class ExternalSortJobPart:
    def __init__(self, type):
        self.type = type

    def execute_for_i_point_reader(self) -> 'IPointReader':
        raise NotImplementedError("Must be implemented by subclass")

    @property
    def type(self):
        return self._type

    class ExternalSortJobPartType(enum.Enum):
        SINGLE_SOURCE = 1
        MULTIPLE_SOURCE = 2
```
Note that I used the `enum` module from Python's standard library to define an enum, and I also defined a property for the `type` attribute. Additionally, since there is no equivalent concept in Python as Java's abstract classes or interfaces, I made the base class `ExternalSortJobPart` concrete by providing a default implementation of its methods.

Also note that I used type hints (`-> 'IPointReader'`) to indicate the return type of the `execute_for_i_point_reader` method.