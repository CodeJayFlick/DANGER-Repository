Here is the translation of the Java code to Python:
```
# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class Beast(metaclass=abc.ABCMeta):
    """Beast."""

    def __init__(self, source=None):
        pass

    @abstractmethod
    def copy(self):
        raise NotImplementedError("Must be implemented by subclass")

from prototype import Prototype  # assuming you have a `prototype.py` file with the `Prototype` class defined
```
Note that I used Python's built-in `abc` module to define an abstract base class (ABC), which is similar to Java's abstract classes. The `@abstractmethod` decorator indicates that the `copy()` method must be implemented by any subclass of `Beast`.