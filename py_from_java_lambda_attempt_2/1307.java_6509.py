Here is the translation of the Java interface `GdbConsoleOperations` into a Python class:

```python
import asyncio

class GdbConsoleOperations:
    async def console(self, command: str) -> asyncio.Future[None]:
        """Execute an arbitrary CLI command, printing output to the CLI console"""
        return await self.console_with_cwr(command, CompletesWithRunning.CAN)

    async def console_with_cwr(self, command: str, cwr: int) -> asyncio.Future[None]:
        # Implement your logic here
        pass

    async def console_capture(self, command: str) -> asyncio.Future[str]:
        """Execute an arbitrary CLI command, capturing its console output"""
        return await self.console_capture_with_cwr(command, CompletesWithRunning.CAN)

    async def console_capture_with_cwr(self, command: str, cwr: int) -> asyncio.Future[str]:
        # Implement your logic here
        pass

class CompletesWithRunning:
    CAN = 0  # or any other value that makes sense for your use case

# Example usage:

async def main():
    operations = GdbConsoleOperations()
    await operations.console("your_command")

asyncio.run(main())
```

Note: I've used the `async` and `await` keywords to define asynchronous functions, which is a common pattern in Python. The `CompletesWithRunning` class has been translated into a simple enum-like class with one constant (`CAN`). You'll need to implement the actual logic for these methods based on your specific requirements.