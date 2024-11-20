Here is a translation of the Java code into equivalent Python:

```Python
import asyncio
from typing import List, Set, Any

class AsyncFence:
    def __init__(self):
        self.participants: List[asyncio.Future] = []
        self.ready: asyncio.Future = None

    async def include(self, future: asyncio.Future) -> 'AsyncFence':
        if self.ready is not None:
            raise ValueError("Fence already ready")
        self.participants.append(future)
        return self

    async def ready(self) -> asyncio.Future:
        if self.ready is None:
            self.ready = asyncio.wait([f for f in self.participants])
        return self.ready

    async def get_pending(self) -> Set[asyncio.Future]:
        pending_futures: List[asyncio.Future] = [f for f in self.participants if not await f.done()]
        return set(pending_futures)
```

Note that Python does not have a direct equivalent to Java's `CompletableFuture` or `CompletionStage`. Instead, we use the built-in `asyncio` library and its `Future` class.