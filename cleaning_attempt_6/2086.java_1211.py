import asyncio
from typing import Any, TypeVar

T = TypeVar('T')

class AsyncLazyValue:
    def __init__(self, supplier: callable) -> None:
        self._supplier = supplier
        self._future = None
        self._last_exception = None

    async def request(self) -> 'asyncio.Future[T]':
        if not self._future:
            self._future = await self._supplier()
            try:
                await asyncio.wait_for(self._future, return_when=asyncio.FUTURE_RESULT)
            except Exception as e:
                with self.lock():
                    self._last_exception = e
                    self._future = None

        if not self._future or self._future.done():
            if self._last_exception:
                return asyncio.Future.from_exception(self._last_exception)
            else:
                return self._future
        else:
            return self._future

    async def provide(self) -> 'asyncio.Future[T]':
        with self.lock():
            if not self._future:
                self._future = await self._supplier()
                try:
                    await asyncio.wait_for(self._future, return_when=asyncio.FUTURE_RESULT)
                except Exception as e:
                    with self.lock():
                        self._last_exception = e
                        self._future = None

        return self._future

    def forget(self) -> None:
        with self.lock():
            self._future = None

    @property
    def lock(self):
        # This is a placeholder for the actual lock object.
        pass

    async def __str__(self) -> str:
        if not self._future:
            return "(lazy)"
        elif not self._future.done():
            return "(lazy-req)"
        elif self._future.exception():
            return "(lazy-err)"
        else:
            return f"({self._future.result()})"

    async def is_busy(self) -> bool:
        with self.lock:
            return self._future and not self._future.done()

    async def is_done(self) -> bool:
        with self.lock:
            return self._future and self._future.done()
