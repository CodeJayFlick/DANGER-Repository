Here is the translation of the Java interface `DbgModelTargetConnector` to a Python abstract class:

```python
from abc import ABC, abstractmethod
import concurrent.futures

class DbgModelTargetConnector(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def get_display(self) -> str:
        """Get the display name of this target connector."""
        raise NotImplementedError("Must be implemented by subclass")

    @abstractmethod
    async def set_active(self) -> concurrent.futures.Future[None]:
        """Set the active state of this target connector."""
        raise NotImplementedError("Must be implemented by subclass")

    @abstractmethod
    def get_parameters(self) -> dict:
        """Get the parameters for this target connector."""
        raise NotImplementedError("Must be implemented by subclass")

    @abstractmethod
    async def launch(self, args: dict) -> concurrent.futures.Future[None]:
        """Launch this target connector with given arguments."""
        raise NotImplementedError("Must be implemented by subclass")
```

Note that I've used the `ABC` class from Python's built-in `abc` module to define an abstract base class. This allows us to use abstract methods, which must be implemented by any concrete subclasses of this class.

I've also replaced Java-specific constructs like interfaces and default methods with their equivalent Python concepts: abstract classes and abstract methods.