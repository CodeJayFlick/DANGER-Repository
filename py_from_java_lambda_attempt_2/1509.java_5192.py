Here is the translation of the given Java code into equivalent Python:

```Python
import socket
from concurrent.futures import Future as CompletableFuture
from abc import ABC, abstractmethod


class LldbGadpServerImpl:
    def __init__(self, addr):
        self.model = LldbModel()
        self.server = GadpSide(self.model, addr)

    class GadpSide(ABC):
        @abstractmethod
        def launch_async_service(self) -> CompletableFuture[None]:
            pass

        def get_local_address(self) -> socket.socket:
            return self.addr


class LldbGadpServerImpl(LldbGadpServerImpl):
    async def start_lldb(self, args: list[str]) -> CompletableFuture[None]:
        future = await self.model.start_lldb(args)
        return future.then_run(lambda __: self.server.launch_async_service())

    @property
    def local_address(self) -> socket.socket:
        return self.server.get_local_address()

    @property
    def is_running(self) -> bool:
        return self.model.is_running

    async def terminate(self):
        await self.model.terminate()
        await self.server.terminate()


class LldbModel(ABC):
    @abstractmethod
    async def start_lldb(self, args: list[str]) -> CompletableFuture[None]:
        pass

    @property
    def is_running(self) -> bool:
        return False  # This should be replaced with actual implementation


class LldbModelImpl(LldbModel):
    async def start_lldb(self, args: list[str]) -> CompletableFuture[None]:
        # This method should be implemented based on the requirements of your project.
        pass

```

Please note that this is a direct translation and may not work as-is in Python. You will need to implement the missing parts (e.g., `start_lldb`, `terminate` methods) according to your specific use case.