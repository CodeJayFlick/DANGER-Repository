Here is the translation of the Java code to Python:
```
import enum

class TSDataType(enum.Enum):
    # Add your data types here (e.g., INT64, FLOAT32, etc.)
    pass

class Configuration:
    def __init__(self, data_type: TSDataType) -> None:
        self._data_type = data_type

    @property
    def data_type(self) -> TSDataType:
        return self._data_type

    def check(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")
```
Note that I've used the `enum` module to define an enumeration type for `TSDataType`, and created a base class `Configuration` with an initializer, property, and abstract method. The rest of the code is straightforward translation from Java to Python.

Also, in the original Java code, there's no implementation provided for the `check()` method, so I've left it as an abstract method (`def check(self) -> None: raise NotImplementedError("Subclasses must implement this method")`) to be implemented by subclasses.