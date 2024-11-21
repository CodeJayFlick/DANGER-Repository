Here is the translation of the given Java interface into a Python class:

```Python
from abc import ABC, abstractmethod


class JdiModelTargetExecutionStateful(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def set_execution_state(self, state: str, reason: str) -> None:
        raise NotImplementedError("Method not implemented")
```

Note that the Python code does not directly translate Java's `default` method. In Python, we use abstract methods (defined using the `@abstractmethod` decorator) to indicate that a subclass must provide an implementation for this method.