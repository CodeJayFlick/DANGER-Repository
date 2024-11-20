import asyncio
from typing import List, Dict, Any

class GdbThreadImpl:
    def __init__(self, manager: 'GdbManager', inferior: 'GdbInferior', id: int):
        self.manager = manager
        self.inferior = inferior
        self.id = id
        self.state = asyncio.Future()
        self.registers = asyncio.LazyObject(self.list_registers)

    def add(self) -> None:
        self.inferior.add_thread(self)
        self.manager.add_thread(self)
        self.state.add_done_callback(lambda f: self.manager.event(f.result(), "thread_state"))

    async def remove(self) -> None:
        await self.state
        self.inferior.remove_thread(self.id)
        self.manager.remove_thread(self.id)

    @property
    def id(self) -> int:
        return self._id

    @property
    def inferior(self) -> 'GdbInferior':
        return self._inferior

    async def setState(self, state: Any, cause: Any, reason: Any) -> bool:
        if await self.state.set_result(state):
            return True
        else:
            return False

    async def execute(self, cmd: Any) -> asyncio.Future:
        match cmd.get_interpreter():
            case 'CLI':
                return (await self.active(True)).then Combine(self.manager.execute(cmd), lambda __, v: v)
            case 'MI2':
                return await self.manager.execute(cmd)

    async def setActive(self, internal: bool) -> asyncio.Future:
        return await self.manager.execute(GdbSetActiveThreadCommand(self.manager, self.id, None, internal))

    async def evaluate(self, expression: str) -> asyncio.Future:
        return await self.execute(GdbEvaluateCommand(self.manager, self.id, None, expression))

    async def setVar(self, var_name: str, val: str) -> asyncio.Future:
        return await self.execute(GdbSetVarCommand(self.manager, self.id, var_name, val))

    async def list_registers(self) -> List[Dict]:
        names = await self.list_register_names()
        sizes_parts = await self.do_evaluate_sizes_in_parts(names)
        result = []
        for part in sizes_parts:
            try:
                sizes = GdbCValueParser.parse_array(part).expect_ints()
            except GdbParseError as e:
                raise AssertionError("GDB did not give an integer array!") from e
            if len(sizes) != len(names):
                raise AssertionError("GDB did not give all the sizes!")
            for size in sizes:
                result.append(GdbRegister(None, None, size))
        return result

    async def list_register_names(self) -> List[str]:
        # todo: implement this method
        pass

    async def do_evaluate_sizes_in_parts(self, names: Collection[str]) -> List[str]:
        parts = self.generate_evaluate_sizes_parts(names)
        if len(parts) == 1:
            return [parts[0]]
        fence = asyncio.create_task(asyncio.sleep(0))
        result = []
        for i in range(len(parts)):
            part = parts[i]
            await fence
            result.append(part)
        return result

    async def generate_evaluate_sizes_parts(self, names: Collection[str]) -> List[str]:
        # todo: implement this method
        pass

    async def do_list_registers(self) -> GdbRegisterSet:
        map_names_by_number = {}
        for i in range(len(names)):
            name = names[i]
            if "" == name:
                continue
            map_names_by_number.put(i, name)
        return await self.do_evaluate_sizes_in_parts(map_names_by_number.values())

    async def list_stack_frames(self) -> List[GdbStackFrame]:
        # todo: implement this method
        pass

    async def read_registers(self, regs: Set[GdbRegister]) -> Dict[GdbRegister, BigInteger]:
        # todo: implement this method
        pass

    async def write_registers(self, reg_vals: Map[GdbRegister, BigInteger]) -> None:
        await self.execute(GdbWriteRegistersCommand(self.manager, self.id, None, reg_vals))

    async def read_memory(self, addr: long, buf: ByteBuffer, len: int) -> RangeSet[Long]:
        return await self.execute(GdbReadMemoryCommand(self.manager, self.id, addr, buf, len))

    async def write_memory(self, addr: long, buf: ByteBuffer, len: int) -> None:
        await self.execute(GdbWriteMemoryCommand(self.manager, self.id, addr, buf, len))

    async def insert_breakpoint(self, loc: str, type: GdbBreakpointType) -> GdbBreakpointInfo:
        return await self.execute(GdbInsertBreakpointCommand(self.manager, self.id, loc, type))

    async def console(self, command: str, cwr: CompletesWithRunning) -> None:
        await self.execute(GdbConsoleExecCommand(self.manager, self.id, None, command, GdbConsoleExecCommand.Output.CONSOLE, cwr))

    async def console_capture(self, command: str, cwr: CompletesWithRunning) -> str:
        return await self.execute(GdbConsoleExecCommand(self.manager, self.id, None, command, GdbConsoleExecCommand.Output.CAPTURE, cwr))

    async def cont(self) -> None:
        await self.execute(GdbContinueCommand(self.manager, self.id))

    async def step(self, suffix: StepCmd) -> None:
        await self.execute(GdbStepCommand(self.manager, self.id, suffix))

    async def kill(self) -> None:
        await self.execute(GdbKillCommand(self.manager, self.id))

    async def detach(self) -> None:
        await self.execute(GdbDetachCommand(self.manager, self.inferior, self.id))

    def dispose(self, reason: Any) -> None:
        self.state.dispose(reason)

    async def get_info(self) -> GdbThreadInfo:
        return await self.manager.get_thread_info(self.id)
