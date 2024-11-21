import asyncio
from typing import TypeVar, Generic

S = TypeVar('S')
H = TypeVar('H')

class AbstractAsyncClientHandler(Generic[S, H], object):
    def __init__(self, server: S, sock) -> None:
        self.server = server
        self.sock = sock

    async def close(self) -> None:
        await asyncio.create_task(self.sock.close())

    async def launch_async(self) -> asyncio.Future[None]:
        # This method should be implemented by the subclass.
        raise NotImplementedError("Subclass must implement this method.")
