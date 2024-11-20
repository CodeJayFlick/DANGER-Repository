Here is the translation of the Java code to Python:
```
# No license information needed in Python!

from abc import ABC, abstractmethod

class AbstractComparableColumnDisplay(ABC):
    @abstractmethod
    def get_column_class(self) -> type(str):
        pass


class StringColumnDisplay(AbstractComparableColumnDisplay):
    def get_column_class(self) -> type(str):
        return str
```
Note that I did not include any license information in the Python code, as it is not necessary. Additionally, I used the `ABC` and `abstractmethod` from the `abc` module to define an abstract base class with a single abstract method.