Here is the translation of the Java code to Python:
```
import asyncio

class DebuggerWrappedConsoleConnection:
    def __init__(self, plugin, target_console):
        pass  # equivalent to super().__init__()

    async def send_line(self, line: str) -> asyncio.Future:
        return await self.target_console.write(line.encode('utf-8'))

# Note: The above Python code is not a direct translation of the Java code,
# but rather an attempt to capture the essence and functionality of the original code.
```
Here's what I did:

1. Replaced `package` with nothing, as packages are not necessary in Python.
2. Imported `asyncio`, which provides support for asynchronous programming (equivalent to Java's `CompletableFuture`).
3. Defined a class `DebuggerWrappedConsoleConnection` that takes two arguments: `plugin` and `target_console`.
4. Replaced the constructor (`public DebuggerWrappedConsoleConnection`) with an initializer method (`__init__`). In Python, constructors are not necessary.
5. Implemented the `send_line` method as an asynchronous function using the `async def` syntax (equivalent to Java's `CompletableFuture< Void > sendLine(String line)`). The return type is now a coroutine object (`asyncio.Future`) instead of a `CompletableFuture`.
6. Replaced `write(line.getBytes(CHARSET))` with `self.target_console.write(line.encode('utf-8'))`. In Python, strings are encoded using UTF-8 by default.

Please note that this translation is not exact and may require further modifications to work correctly in your specific use case.