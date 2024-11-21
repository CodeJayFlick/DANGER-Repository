Here's your Java interface translated into a Python abstract class:

```Python
from abc import ABC, abstractmethod


class DatabaseConnectionProvider(ABC):
    @abstractmethod
    def configure(self, config: dict) -> None:
        """Applies connection configuration to this connection provider."""
        pass

    @abstractmethod
    def initialize(self) -> None:
        """Initialize the connection provider using the configuration supplied earlier via #configure(DatabaseConnectionConfig)."""
        raise Exception("Not implemented")

    @abstractmethod
    def close(self) -> None:
        """Forcefully close all resources held by this provider, even if this instance is still referenced."""
        pass


class AutoCloseable(ABC):
    @abstractmethod
    def close(self) -> None:
        """Forcefully close all resources held by this provider, even if this instance is still referenced."""
        raise Exception("Not implemented")
```

Note that Python does not have direct equivalents to Java interfaces or abstract classes. However, we can achieve similar functionality using abstract base classes (ABCs).