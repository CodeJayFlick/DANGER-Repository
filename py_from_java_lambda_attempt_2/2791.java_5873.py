Here is a translation of the Java code into equivalent Python:

```Python
from abc import ABCMeta, abstractmethod

class DBAnnotatedField(metaclass=ABCMeta):
    def __init__(self, column: str, indexed=False) -> None:
        self.column = column
        self.indexed = indexed

    @property
    def codec(self) -> type['DBFieldCodec']:
        return DefaultCodec

    class DefaultCodec(ABCMeta):
        @abstractmethod
        def encode(self, value: 'Void') -> dict:
            pass

        @abstractmethod
        def decode(self, data: dict) -> 'Void':
            pass


class Void(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self) -> None:
        pass
```

Please note that Python does not have direct equivalent of Java's annotations. The above code is a translation and may require some adjustments based on the actual use case.

Here are some key differences:

- In Python, we don't need to specify types for method parameters or return values like in Java.
- We can define classes inside other classes using nested class definitions (like `DefaultCodec`).
- The equivalent of Java's interfaces is abstract base classes (`ABCMeta`) and the equivalent of Java's annotations are just regular functions.