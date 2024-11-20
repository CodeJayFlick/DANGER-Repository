Here is the translation of the Java interface into a Python class:

```Python
from abc import ABC, abstractmethod


class DbgModelTargetSessionContainer(ABC):
    @abstractmethod
    def session_added(self, session: object, cause: str) -> None:
        pass

    @abstractmethod
    def session_removed(self, sessionId: int, cause: str) -> None:
        pass

    @abstractmethod
    def get_target_session(self, session: object) -> object:
        pass


class DbgModelTargetSessionContainerImpl(DbgModelTargetSessionContainer):
    def __init__(self):
        self.target_sessions = {}

    def session_added(self, session: object, cause: str) -> None:
        # refresh()
        pass

    def session_removed(self, sessionId: int, cause: str) -> None:
        pass

    def get_target_session(self, session: object) -> object:
        return self.target_sessions.get(session)
```

Please note that Python does not have direct support for interfaces like Java. Instead, we use abstract base classes (ABCs) to define the interface and provide a default implementation if needed.