from abc import ABCMeta, abstractmethod
import asyncio
import concurrent.futures
import typing as t

class JdiManager(metaclass=ABCMeta):
    @abstractmethod
    async def new_instance(self) -> 'JdiManager':
        pass

    @abstractmethod
    async def terminate(self) -> None:
        pass

    @abstractmethod
    async def add_state_listener(
            self, vm: t.Any, listener: t.Callable[[t.Any], None]
    ) -> None:
        pass

    @abstractmethod
    async def remove_state_listener(
            self, vm: t.Any, listener: t.Callable[[t.Any], None]
    ) -> None:
        pass

    @abstractmethod
    async def add_events_listener(self, vm: t.Any, listener: t.Callable[[t.Any], None]) -> None:
        pass

    @abstractmethod
    async def remove_events_listener(
            self, vm: t.Any, listener: t.Callable[[t.Any], None]
    ) -> None:
        pass

    @abstractmethod
    async def add_target_output_listener(self, listener: t.Callable[[str], None]) -> None:
        pass

    @abstractmethod
    async def remove_target_output_listener(self, listener: t.Callable[[str], None]) -> None:
        pass

    @abstractmethod
    async def add_console_output_listener(self, listener: t.Callable[[str], None]) -> None:
        pass

    @abstractmethod
    async def remove_console_output_listener(self, listener: t.Callable[[str], None]) -> None:
        pass

    @abstractmethod
    async def get_vm(self, id: str) -> t.Any:
        pass

    @abstractmethod
    async def get_known_vms(self) -> dict[str, t.Any]:
        pass

    @abstractmethod
    async def send_interrupt_now(self) -> None:
        pass

    @abstractmethod
    async def add_vm(
            self,
            cx: t.Any,
            args: list[t.Any] | dict[str, t.Any]
    ) -> concurrent.futures.Future[t.Any]:
        pass

    @abstractmethod
    async def remove_vm(self, vm: t.Any) -> concurrent.futures.Future[None]:
        pass

    @abstractmethod
    async def console(self, command: str) -> concurrent.futures.Future[None]:
        pass

    @abstractmethod
    async def console_capture(self, command: str) -> concurrent.futures.Future[str]:
        pass

    @abstractmethod
    async def list_vms(self) -> concurrent.futures.Future[dict[str, t.Any]]:
        pass

    @abstractmethod
    async def list_available_processes(self) -> concurrent.futures.Future[list[tuple[int, str]]]:
        pass

    @abstractmethod
    async def get_virtual_machine_manager(self) -> t.Any:
        pass

    @abstractmethod
    async def get_event_handler(self, vm: t.Any) -> t.Any:
        pass


class JdiManagerImpl(JdiManager):
    # Implement the abstract methods here.
