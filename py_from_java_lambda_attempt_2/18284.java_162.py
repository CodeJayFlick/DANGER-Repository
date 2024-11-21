Here's your Java interface translated into a Python abstract class:

```Python
from abc import ABC, abstractmethod


class IPageReader(ABC):
    @abstractmethod
    def get_all_satisfied_page_data(self) -> dict:
        pass

    @abstractmethod
    def get_statistics(self) -> dict:
        pass

    @abstractmethod
    def set_filter(self, filter: object) -> None:
        pass

    @property
    @abstractmethod
    def is_modified(self) -> bool:
        pass


class BatchData(dict):
    pass


class Statistics(dict):
    pass


class Filter(object):
    pass
```

Please note that Python does not have direct equivalents for Java's interfaces or abstract classes. However, we can achieve similar functionality using Python's built-in features like abstract base classes (ABCs) and the `@abstractmethod` decorator.

In this translation:

- The interface methods are translated into abstract methods in an ABC.
- A new class `BatchData`, `Statistics`, and `Filter` are created to represent their Java counterparts. These classes do not have any specific functionality, they just exist as placeholders for the data types used by these objects.
- Python does not support default values or overloading of methods like Java's interfaces. Therefore, we can't directly translate some parts of your original code into Python.

This translation should give you a good starting point to work with in Python.