Here is the translation of the given Java interface into a Python class:

```Python
import asyncio
from typing import Any, Dict

class LldbBreakpointInsertions:
    async def insert_breakpoint(self, loc: str, type: int) -> Dict[str, Any]:
        return await self.insert_breakpoint(loc=loc, addr=None, len=1, breakpoint_type=type)

    async def insert_breakpoint(self, loc: str) -> Dict[str, Any]:
        return await self.insert_breakpoint(loc=loc, addr=None, len=1, breakpoint_type=LldbBreakpointType.BREAKPOINT.value)

    async def insert_breakpoint(self, addr: int) -> Dict[str, Any]:
        return await self.insert_breakpoint(loc=None, addr=addr, len=1, breakpoint_type=LldbBreakpointType.BREAKPOINT.value)

    async def insert_breakpoint(self, addr: int, len: int, type: int) -> Dict[str, Any]:
        pass  # This method is not implemented in the given Java interface

class LldbBreakpointInfo:
    pass  # This class is not defined in the given Java interface

LldbBreakpointType = enum('BREAKPOINT', 'WATCHPOINT')
```

Note that Python does not have a direct equivalent to Java's `CompletableFuture` or `enum`. The above code uses asynchronous functions (`async def`) and dictionaries to represent the return values.