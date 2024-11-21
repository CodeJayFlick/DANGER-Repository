Here is the translation of the Java code to Python:
```
import abc

class AutoConfigStateField(metaclass=abc.ABCMeta):
    def __init__(self):
        raise AssertionError()

    @property
    def codec(self) -> type:
        return DefaultConfigFieldCodec

@AutoConfigStateField.register
class DefaultConfigFieldCodec(ABC):
    pass
```
Note that Python does not have a direct equivalent to Java's `@interface` or `@Target`, so I've used the `metaclass=abc.ABCMeta` syntax to define an abstract base class. The `__init__` method is also required in Python, but it can simply raise an error as per your original code.

The `codec` property is defined using a getter function, which returns the type of the default codec (`DefaultConfigFieldCodec`).