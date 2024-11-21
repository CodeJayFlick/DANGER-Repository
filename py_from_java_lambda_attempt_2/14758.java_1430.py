Here is the translation of the Java code to Python:
```
# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class Mage(metaclass=abc.ABCMeta):
    """Mage."""

    def __init__(self, source=None):
        pass

    @abstractmethod
    def copy(self):
        raise NotImplementedError("Must be implemented by subclass")
```
Note that I used the `metaclass` parameter to specify that this is an abstract class using ABC (Abstract Base Classes) from Python's standard library. The rest of the code translates fairly directly, with some minor adjustments for Python syntax and semantics.

Also, since there is no direct equivalent to Java's `@EqualsAndHashCode` and `@NoArgsConstructor` annotations in Python, I omitted them as they are not necessary or meaningful in a Python context.