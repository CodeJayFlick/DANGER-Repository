Here is the translation of the Java code to Python:
```python
import asyncio
from typing import CompletableFuture  # Not actually used in this example, but included for completeness

class SpawnedMi2GdbManagerTest2:
    async def start_manager(self, manager: GdbManager) -> None:
        try:
            await manager.start(["-i", "mi2"])
            await manager.run_rc()
        except Exception as e:
            raise AssertionError(str(e))

    async def get_pty_factory(self) -> PtyFactory:
        # TODO: Choose by host OS
        return LinuxPtyFactory()

class GdbManager:
    DEFAULT_GDB_CMD = ""

    async def start(self, *args):
        pass

    async def run_rc(self):
        pass

class PtyFactory:
    pass

class LinuxPtyFactory(PtyFactory):
    pass
```
Note that I've used the `async` and `await` keywords to indicate asynchronous code, since Python 3.5 introduced support for coroutines with these features. The rest of the translation is straightforward: Java classes become Python classes, methods become functions or async methods, and exceptions are raised using the built-in `raise` statement.

Also note that I've omitted some details from the original Java code, such as imports and annotations (e.g., `@Ignore`). These were not relevant to the translation process.