Here is the translation of the Java interface `DbgMemoryOperations` into a Python class:

```python
import asyncio

class DbgMemoryOperations:
    async def read_memory(self, addr: int, buf: bytearray, len: int) -> dict:
        # TO DO: implement your logic here to read memory and return ranges successfully read
        pass

    async def read_memory(self, addr: int, buf: bytearray) -> dict:
        return await self.read_memory(addr, buf, len(buf))

    async def write_memory(self, addr: int, buf: bytearray, len: int) -> asyncio.Future:
        # TO DO: implement your logic here to write memory and return a future that completes when the write succeeds
        pass

    async def write_memory(self, addr: int, buf: bytearray) -> asyncio.Future:
        return await self.write_memory(addr, buf, len(buf))
```

Note:

* In Python, we don't have direct equivalents of Java interfaces or classes. Instead, we use abstract base classes (ABCs) to define a common interface for subclasses.
* The `async` and `await` keywords are used in Python 3.x to create asynchronous functions that can be awaited using the `await` keyword.
* In this translation, I've replaced the Java `CompletableFuture` with Python's built-in support for coroutines (using `async/await`) and futures (using `asyncio.Future`).