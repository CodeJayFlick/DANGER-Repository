Here's the equivalent Python code for the given Java interface:

```Python
from abc import ABC, abstractmethod


class TargetConsole(ABC):
    CHARSET = 'utf-8'

    class Channel:
        STDOUT = 0
        STDERR = 1

    @abstractmethod
    def write(self, data: bytes) -> None:
        pass
```

Note that Python does not have direct equivalents for Java's `interface` or `enum`. Instead, we use abstract base classes (ABCs) and a class to represent the enum. The `write` method is declared as an abstract method using the `@abstractmethod` decorator, which means it must be implemented by any subclass of `TargetConsole`.