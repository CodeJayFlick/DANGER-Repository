Here is the translation of the given Java interface into a Python class:

```Python
from concurrent.futures import Future as CompletableFuture
import abc


class DbgModelTargetEventOption(metaclass=abc.ABCMeta):
    @abstractmethod
    def get_option(self) -> int:
        pass

    @abstractmethod
    async def set_option(self, ordinal: int) -> CompletableFuture[None]:
        pass
```

Note that in Python, we don't have direct equivalent of Java's `interface` keyword. Instead, we use abstract base classes (ABCs). The `metaclass=abc.ABCMeta` is used to make the class an ABC.

The `get_option` method is translated from the Java method with the same name and return type (`Integer`). In Python, it returns an integer directly.

The `set_option` method in Java takes a single argument of type `int`, which corresponds to the `ordinal` parameter in the Python version. The return value in Java was a `CompletableFuture< Void >`, which is translated into a coroutine that returns a `Future[None]`.