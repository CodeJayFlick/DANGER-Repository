Here is the translation of the Java interface `GdbEventsListenerAdapter` into a Python abstract class:

```python
from abc import ABC, abstractmethod

class GdbEventsListenerAdapter(ABC):
    @abstractmethod
    def inferior_added(self, inferior: object, cause: str) -> None:
        pass

    @abstractmethod
    def inferior_removed(self, inferior_id: int, cause: str) -> None:
        pass

    @abstractmethod
    def inferior_selected(self, inferior: object, cause: str) -> None:
        pass

    @abstractmethod
    def inferior_started(self, inferior: object, cause: str) -> None:
        pass

    @abstractmethod
    def inferior_exited(self, inferior: object, cause: str) -> None:
        pass

    @abstractmethod
    def inferior_state_changed(
            self,
            inf: object,
            threads: list[object],
            state: str,
            thread: object,
            cause: str,
            reason: str
    ) -> None:
        pass

    @abstractmethod
    def thread_created(self, thread: object, cause: str) -> None:
        pass

    @abstractmethod
    def thread_state_changed(
            self,
            thread: object,
            state: str,
            cause: str,
            reason: str
    ) -> None:
        pass

    @abstractmethod
    def thread_exited(self, thread_id: int, inferior: object, cause: str) -> None:
        pass

    @abstractmethod
    def thread_selected(
            self,
            thread: object,
            frame: object,
            cause: str
    ) -> None:
        pass

    @abstractmethod
    def library_loaded(self, inferior: object, name: str, cause: str) -> None:
        pass

    @abstractmethod
    def library_unloaded(self, inferior: object, name: str, cause: str) -> None:
        pass

    @abstractmethod
    def breakpoint_created(self, info: object, cause: str) -> None:
        pass

    @abstractmethod
    def breakpoint_modified(
            self,
            new_info: object,
            old_info: object,
            cause: str
    ) -> None:
        pass

    @abstractmethod
    def breakpoint_deleted(self, info: object, cause: str) -> None:
        pass

    @abstractmethod
    def memory_changed(self, inferior: object, addr: int, len: int, cause: str) -> None:
        pass

    @abstractmethod
    def param_changed(self, param: str, value: str, cause: str) -> None:
        pass
```

Note that I've used the `ABC` class from Python's built-in `abc` module to define an abstract base class. The methods are declared as abstract using the `@abstractmethod` decorator.