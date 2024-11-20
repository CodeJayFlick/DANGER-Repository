Here is the translation of the Java interface `DbgProcess` into Python:

```Python
from abc import ABC, abstractmethod
import concurrent.futures

class DbgProcess(ABC):
    @abstractmethod
    def get_id(self) -> int:
        pass

    @abstractmethod
    def get_pid(self) -> int | None:
        pass

    @abstractmethod
    def get_exit_code(self) -> int | None:
        pass

    @abstractmethod
    def get_thread(self, id: str) -> 'DbgThread' | None:
        pass

    @abstractmethod
    def get_module(self, name: str) -> 'DbgModule' | None:
        pass

    @abstractmethod
    def get_known_threads(self) -> dict[str, 'DbgThread']:
        pass

    @abstractmethod
    def list_threads(self) -> concurrent.futures.Future[dict[str, 'DbgThread']]:
        pass

    @abstractmethod
    def get_known_modules(self) -> dict[str, 'DbgModule']:
        pass

    @abstractmethod
    def list_modules(self) -> concurrent.futures.Future[dict[str, 'DbgModule']]:
        pass

    @abstractmethod
    def get_known_mappings(self) -> dict[int, DbgSectionImpl]:
        pass

    @abstractmethod
    def list_mappings(self) -> concurrent.futures.Future[dict[int, DbgSectionImpl]]:
        pass

    @abstractmethod
    def set_active(self) -> concurrent.futures.Future[None]:
        pass

    @abstractmethod
    def file_exec_and_symbols(self, file: str) -> concurrent.futures.Future[None]:
        pass

    @abstractmethod
    def run(self) -> concurrent.futures.Future['DbgThread']:
        pass

    @abstractmethod
    def attach(self, pid: int) -> concurrent.futures.Future[frozenset['DbgThread']]:
        pass

    @abstractmethod
    def reattach(self, target_attachable: TargetAttachable) -> concurrent.futures.Future[frozenset['DbgThread']]:
        pass

    @abstractmethod
    def console_capture(self, command: str) -> concurrent.futures.Future[str]:
        pass

    @abstractmethod
    def cont(self) -> concurrent.futures.Future[None]:
        pass

    @abstractmethod
    def step(self, suffix: ExecSuffix) -> concurrent.futures.Future[None]:
        pass

    @abstractmethod
    def step(self, args: dict[str, str]) -> concurrent.futures.Future[None]:
        pass

    @abstractmethod
    def evaluate(self, expression: str) -> concurrent.futures.Future[str]:
        pass

    @abstractmethod
    def detach(self) -> concurrent.futures.Future[None]:
        pass

    @abstractmethod
    def kill(self) -> concurrent.futures.Future[None]:
        pass

    @abstractmethod
    def remove(self) -> concurrent.futures.Future[None]:
        pass
```

Note that I used `ABC` and `abstractmethod` from the Python standard library to define an abstract class.