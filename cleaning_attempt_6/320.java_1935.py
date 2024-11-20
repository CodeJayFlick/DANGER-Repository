from typing import Set, Collection, Dict, Any

class LogicalBreakpointsChangeListener:
    def __init__(self):
        pass

    def on_change(self) -> None:
        pass


class DebuggerLogicalBreakpointService:
    default_provider = "DebuggerLogicalBreakpointServicePlugin"

    def __init__(self):
        self._breakpoints: Set["LogicalBreakpoint"] = set()
        self._listeners: List[LogicalBreakpointsChangeListener] = []

    @property
    def breakpoints(self) -> Set["LogicalBreakpoint"]:
        return self._breakpoints

    def add_listener(self, listener: LogicalBreakpointsChangeListener):
        if not isinstance(listener, LogicalBreakpointsChangeListener):
            raise TypeError("Listener must be an instance of LogicalBreakpointsChangeListener")
        self._listeners.append(listener)

    def remove_listener(self, listener: LogicalBreakpointsChangeListener) -> None:
        try:
            self._listeners.remove(listener)
        except ValueError:
            pass

    @staticmethod
    def program_or_trace(loc: ProgramLocation,
                         prog_func: Callable[[Program, Address], Any],
                         trace_func: Callable[[Trace, Address], Any]) -> Any:
        if isinstance(loc.get_program(), TraceProgramView):
            return trace_func(TraceProgramView.view().get_trace(), loc.get_byte_address())
        else:
            return prog_func(loc.get_program(), loc.get_byte_address())

    def compute_enablement(self, col: Collection["LogicalBreakpoint"], program: Program) -> Enablement:
        en = Enablement.NONE
        for lb in col:
            en = en.same_address(lb.compute_enablement_for_program(program))
        return en

    def compute_enablement(self, col: Collection["LogicalBreakpoint"]) -> Enablement:
        if len(col) == 0:
            return Enablement.NONE
        else:
            return self.compute_enablement(col, None)

    @staticmethod
    async def place_breakpoint_at(program: Program, address: Address,
                                   length: int, kinds: List[TraceBreakpointKind]) -> CompletableFuture[Void]:
        pass

    @staticmethod
    async def place_breakpoint_at(trace: Trace, address: Address, length: int,
                                  kinds: List[TraceBreakpointKind]) -> CompletableFuture[Void]:
        pass

    async def place_breakpoint_at(self, loc: ProgramLocation, length: int,
                                   kinds: List[TraceBreakpointKind]) -> CompletableFuture[Void]:
        if isinstance(loc.get_program(), TraceProgramView):
            return self.place_breakpoint_at(TraceProgramView.view().get_trace(),
                                            loc.get_byte_address(), length, kinds)
        else:
            return self.place_breakpoint_at(loc.get_program(), loc.get_byte_address(), length, kinds)

    async def enable_all(self, col: Collection["LogicalBreakpoint"], trace: Trace) -> CompletableFuture[Void]:
        pass

    async def disable_all(self, col: Collection["LogicalBreakpoint"], trace: Trace) -> CompletableFuture[Void]:
        pass

    async def delete_all(self, col: Collection["LogicalBreakpoint"], trace: Trace) -> CompletableFuture[Void]:
        pass
