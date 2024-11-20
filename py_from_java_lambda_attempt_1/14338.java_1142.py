Here is the translation of the Java interface into a Python abstract class:

```Python
from abc import ABC, abstractmethod

class ConsoleAdministrationSrv(ABC):
    """Console interface for lottery administration."""

    @abstractmethod
    def get_all_submitted_tickets(self) -> None:
        """Get all submitted tickets."""
        pass

    @abstractmethod
    def perform_lottery(self) -> None:
        """Draw lottery numbers."""
        pass

    @abstractmethod
    def reset_lottery(self) -> None:
        """Begin new lottery round."""
        pass
```

Note that Python does not have a direct equivalent to Java's interface. Instead, we use an abstract class with abstract methods (methods declared with the `@abstractmethod` decorator). This allows us to define a blueprint for other classes to follow while still providing some basic functionality.