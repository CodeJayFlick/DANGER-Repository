Here is the translation of the Java interface `LayerRowWindowReader` to a Python class:

```python
import io
from abc import ABC, abstractmethod


class LayerRowWindowReader(ABC):
    @abstractmethod
    def next(self) -> bool:
        pass

    @abstractmethod
    def ready_for_next(self) -> None:
        pass

    @property
    @abstractmethod
    def data_types(self) -> list[TSDataType]:
        pass

    @property
    @abstractmethod
    def current_window(self) -> RowWindow:
        pass


class TSDataType(ABC):
    @abstractmethod
    pass


# You would need to define the RowWindow class and its properties
```

Note that I've used Python's type hints (`->`) for method return types, as well as property getters. The `TSDataType` is an abstract base class (ABC) in this translation, but you may want to replace it with a concrete implementation depending on your use case.

Also note that the Java interface has been translated into a Python ABC (Abstract Base Class), which allows for more flexibility and extensibility compared to a traditional Python class.