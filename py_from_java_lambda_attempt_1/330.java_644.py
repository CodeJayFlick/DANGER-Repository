Here is the translation of the given Java code into equivalent Python:

```Python
import asyncio
from typing import List, Map, Any

class AsyncPcodeExecutor:
    def __init__(self, language: str, arithmetic: Any, state: Any):
        pass  # Not implemented in this example

    async def step_op_async(self, op: Any, frame: Any, library: Any) -> asyncio.Future:
        if op.get_opcode() == PcodeOp.CBRANCH:
            return await self.execute_conditional_branch_async(op, frame)
        else:
            self.step_op(op, frame, library)
            return asyncio.Future()

    async def step_async(self, frame: Any, library: Any) -> asyncio.Future:
        try:
            op = frame.next_op()
            return await self.step_op_async(op, frame, library)
        except PcodeExecutionException as e:
            e.frame = frame
            return asyncio.from_future(e)
        except Exception as e:
            return asyncio.from_future(PcodeExecutionException("Exception during pcode execution", frame, e))

    async def execute_conditional_branch_async(self, op: Any, frame: Any) -> asyncio.Future:
        cond_var = op.get_input(1)
        cond = await self.state.get(cond_var)
        if arithmetic.is_true(cond):
            await self.execute_branch(op, frame)

    async def execute_async(self, program: Any, library: Any) -> asyncio.Future:
        return await self.execute_async(program.code, program.userop_names, library)

    @asyncio.coroutine
    def execute_async_loop(self, frame: Any, library: Any) -> asyncio.Future:
        if frame.is_finished():
            return asyncio.Future()
        else:
            future = yield from self.step_async(frame, library)
            return await self.execute_async_loop(frame, library)

    async def execute_async(self, code: List[Any], userop_names: Map[int, str], library: Any) -> asyncio.Future:
        frame = PcodeFrame(language=language, code=code, userop_names=userop_names)
        return await self.execute_async_loop(frame, library)


class PcodeExecutionException(Exception):
    def __init__(self, message: str, frame: Any, e: Exception):
        super().__init__(message)
        self.frame = frame
        self.caused_by = e


# Example usage:
async def main():
    executor = AsyncPcodeExecutor(language="Sleigh", arithmetic=None, state=None)  # Not implemented in this example

    program = PcodeProgram(code=[op1, op2], userop_names={1: "userop_name"})
    library = SleighUseropLibrary(None)

    future = await executor.execute_async(program=program, library=library)
    print(future.result())

asyncio.run(main())
```

Please note that this is a direct translation of the given Java code into Python. It might not be perfect and may require adjustments based on your specific use case.