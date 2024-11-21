Here is a translation of the Java interface into equivalent Python code:

```Python
import asyncio

class DbgModelTargetMemoryContainer:
    def get_target_memory(self, region):
        # Implement this method in your subclass
        pass

    async def read_memory(self, address: int, length: int) -> bytes:
        # Implement this method in your subclass
        pass

    async def write_memory(self, address: int, data: bytes) -> None:
        # Implement this method in your subclass
        pass

    async def request_elements(self, refresh: bool) -> None:
        # Implement this method in your subclass
        pass
```

Note that Python does not have direct equivalents to Java's interfaces or classes. Instead, we define a class `DbgModelTargetMemoryContainer` with methods that are meant to be implemented by subclasses.

The `read_memory`, `write_memory`, and `request_elements` methods use the `asyncio` library to create asynchronous functions (coroutines). This is equivalent to Java's CompletableFuture API for handling asynchronous operations.