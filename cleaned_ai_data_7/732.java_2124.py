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
