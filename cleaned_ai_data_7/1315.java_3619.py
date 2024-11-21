import asyncio
from abc import ABC, abstractmethod


class GdbManager(ABC):
    @abstractmethod
    async def start(self) -> None:
        pass

    @abstractmethod
    async def run_rc(self) -> None:
        pass

    @abstractmethod
    async def console_loop(self) -> None:
        pass

    @abstractmethod
    async def terminate(self) -> None:
        pass

    @abstractmethod
    def is_alive(self) -> bool:
        pass

    @abstractmethod
    def add_state_listener(self, listener: 'GdbStateListener') -> None:
        pass

    @abstractmethod
    def remove_state_listener(self, listener: 'GdbStateListener') -> None:
        pass

    @abstractmethod
    async def send_interrupt_now(self) -> None:
        pass

    @abstractmethod
    async def cancel_current_command(self) -> None:
        pass

    @abstractmethod
    async def get_state(self) -> 'GdbState':
        pass

    @abstractmethod
    async def wait_for_state(self, state: 'GdbState') -> None:
        pass

    @abstractmethod
    async def wait_for_prompt(self) -> None:
        pass

    @abstractmethod
    async def claim_stopped(self) -> None:
        pass

    @abstractmethod
    async def add_inferior(self) -> 'GdbInferior':
        pass

    @abstractmethod
    async def available_inferior(self) -> 'GdbInferior':
        pass

    @abstractmethod
    async def remove_inferior(self, inferior: 'GdbInferior') -> None:
        pass

    @abstractmethod
    async def interrupt(self) -> None:
        pass

    @abstractmethod
    async def list_inferiors(self) -> dict[int, 'GdbInferior']:
        pass

    @abstractmethod
    async def list_breakpoints(self) -> dict[long, 'GdbBreakpointInfo']:
        pass

    @abstractmethod
    async def disable_breakpoints(self, numbers: long...) -> None:
        pass

    @abstractmethod
    async def enable_breakpoints(self, numbers: long...) -> None:
        pass

    @abstractmethod
    async def delete_breakpoints(self, numbers: long...) -> None:
        pass

    @abstractmethod
    async def list_available_processes(self) -> list['GdbProcessThreadGroup']:
        pass

    @abstractmethod
    async def info_os(self, type: str) -> 'GdbTable':
        pass

    @abstractmethod
    def get_mi2_pty_name(self) -> str:
        pass

    @abstractmethod
    def get_pty_description(self) -> str:
        pass


class GdbThread(ABC):
    @abstractmethod
    async def step(self, cmd: 'StepCmd') -> None:
        pass


class StepCmd(ABC):
    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def get_mi2(self) -> str:
        pass

    @abstractmethod
    def get_cli(self) -> str:
        pass


class GdbInferior(ABC):
    @abstractmethod
    async def set_active(self) -> None:
        pass

    @abstractmethod
    def __str__(self) -> str:
        pass


class GdbBreakpointInfo(ABC):
    @abstractmethod
    def get_id(self) -> long:
        pass

    @abstractmethod
    def get_location(self) -> str:
        pass

    @abstractmethod
    def is_enabled(self) -> bool:
        pass


class GdbProcessThreadGroup(ABC):
    @abstractmethod
    async def list_processes(self) -> list['GdbProcess']:
        pass


class GdbState(ABC):
    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def is_running(self) -> bool:
        pass

    @abstractmethod
    def is_stopped(self) -> bool:
        pass


class GdbTable(ABC):
    @abstractmethod
    async def get_table(self) -> dict[str, list[str]]:
        pass


# Example usage:

async def main():
    manager = await GdbManager.newInstance(PtyFactory())
    await manager.start()
    await manager.run_rc()
    await manager.console_loop()

if __name__ == "__main__":
    asyncio.run(main())

