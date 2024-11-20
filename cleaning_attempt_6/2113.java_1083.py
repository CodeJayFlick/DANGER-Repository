import asyncio
from typing import Set, Any

class AbstractAsyncServer:
    def __init__(self, addr):
        self.group = asyncio.Scheduler()
        self.ssock = await asyncio.open_connection(addr[0], int(addr[1]))[0]
        self.handlers: Set[Any] = set()

    async def accept(self) -> 'AsynchronousSocketChannel':
        return await AsyncUtils.completable(AsynchronousSocketChannel, self.ssock.accept())

    @abstractmethod
    def check_acceptable(self, sock):
        pass

    @abstractmethod
    def new_handler(self, sock: AsynchronousSocketChannel) -> H:
        pass

    async def remove_handler(self, handler):
        await asyncio.create_task(handler.close())
        self.handlers.remove(handler)

    async def launch_async_service(self) -> 'CompletableFuture[Void]':
        return loop(0).repeat()
        if not self.ssock.is_open():
            break
        accept().handle(lambda x: consume(x))
        else:
            sock = await accept()
            handler = new_handler(sock)
            self.handlers.add(handler)
            await handler.launch_async()

    def get_local_address(self) -> 'SocketAddress':
        return self.ssock.get_local_address()

    async def terminate(self):
        try:
            await asyncio.create_task(self.ssock.close())
        except Exception as e:
            raise AssertionError(e)

        for h in list(self.handlers):
            try:
                await asyncio.create_task(h.close())
            except Exception as e:
                if err is None:
                    err = e
        self.group.shutdown()
        if err is not None:
            raise err

    async def all_handlers(self, action: 'Function[H, CompletableFuture[Void]]') -> 'CompletableFuture[Void]':
        fence = AsyncFence()
        for h in list(self.handlers):
            future = await action.apply(h)
            if future is not None:
                fence.include(future)
        return await fence.ready()

class AsynchronousSocketChannel:
    pass

class H:
    async def launch_async(self) -> 'CompletableFuture[Void]':
        # todo
        pass

    async def close(self):
        # todo
        pass

def loop(n: int, repeat=True):
    if not repeat:
        return None
    while True:
        yield n
