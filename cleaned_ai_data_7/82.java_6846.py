import asyncio

class DebuggerWrappedConsoleConnection:
    def __init__(self, plugin, target_console):
        pass  # equivalent to super().__init__()

    async def send_line(self, line: str) -> asyncio.Future:
        return await self.target_console.write(line.encode('utf-8'))

# Note: The above Python code is not a direct translation of the Java code,
# but rather an attempt to capture the essence and functionality of the original code.
