Here's your Java interface translated into a Python abstract class:

```Python
from abc import ABC, abstractmethod

class DefaultExpression(ABC):
    @abstractmethod
    def init(self) -> bool:
        pass

    @property
    @abstractmethod
    def is_default(self) -> bool:
        pass
```

Note that in Python, we don't have direct equivalents of Java interfaces. Instead, we use abstract base classes (ABCs). The `@abstractmethod` decorator indicates a method that must be implemented by any subclass.