Here is the translation of the Java code to Python:
```
import asyncio
from abc import ABC, abstractmethod


class AbstractDbgModel(ABC):
    @abstractmethod
    def get_manager(self) -> object:
        pass

    @abstractmethod
    async def start_dbg_eng(self, args: list[str]) -> None:
        ...

    @abstractmethod
    def is_running(self) -> bool:
        pass

    @abstractmethod
    def terminate(self) -> None:
        raise Exception("Not implemented")

    @abstractmethod
    def get_address_factory(self) -> object:
        pass

    @abstractmethod
    async def get_session(self) -> object:
        ...

    @abstractmethod
    def add_model_object(self, obj: object, target_obj: object) -> None:
        pass

    @abstractmethod
    def get_model_object(self, obj: object) -> object:
        pass

    @abstractmethod
    def delete_model_object(self, obj: object) -> None:
        pass
```
Note that I used the `asyncio` library to translate the Java `CompletableFuture` to Python's asynchronous functions. Also, I kept the abstract methods as is, since they don't have any specific implementation in this code snippet.

Please note that this translation assumes a basic understanding of both Java and Python programming languages. If you're not familiar with either language, it may be helpful to review their syntax and semantics before working on translating code between them.