Here is the translation of the given Java code into equivalent Python:

```Python
from typing import Set, Dict, Any

class MappedLogicalBreakpoint:
    def __init__(self, program: Any, prog_addr: int, length: int, kinds: Set):
        self.length = length
        self.kinds = kinds
        self.prog_break = ProgramBreakpoint(program, prog_addr, length, kinds)
        self.trace_breaks: Dict[Any, TraceBreakpointSet] = {}

    def __str__(self) -> str:
        return f"<{type(self).__name__} prog={self.prog_break}, traces={list(self.trace_breaks.values())}>"

    @property
    def has_program_breakpoint(self):
        return self.prog_break.get_bookmark() is not None

    def isEmpty(self) -> bool:
        if not self.prog_break.is_empty():
            return False
        for breaks in self.trace_breaks.values():
            if not breaks.is_empty():
                return False
        return True

    @staticmethod
    def require_recorder(model_service: Any, trace: Any):
        recorder = model_service.get_recorder(trace)
        if recorder is None:
            raise AssertionError("This trace is not live")
        return recorder

    def enable_for_program(self) -> None:
        self.prog_break.enable()

    def disable_for_program(self) -> None:
        self.prog_break.disable()

    def delete_for_program(self) -> None:
        self.prog_break.delete_from_program()

    async def enable_for_trace(self, trace: Any):
        actions = BreakpointActionSet()
        breaks = self.trace_breaks.get(trace)
        if breaks is not None:
            breaks.plan_enable(actions, self.length, self.kinds)
        for breaks in self.trace_breaks.values():
            breaks.plan_enable(actions, self.length, self.kinds)
        return await actions.execute()

    async def disable_for_trace(self, trace: Any):
        actions = BreakpointActionSet()
        breaks = self.trace_breaks.get(trace)
        if breaks is not None:
            breaks.plan_disable(actions, self.length, self.kinds)
        for breaks in self.trace_breaks.values():
            breaks.plan_disable(actions, self.length, self.kinds)
        return await actions.execute()

    async def delete_for_trace(self, trace: Any):
        actions = BreakpointActionSet()
        breaks = self.trace_breaks.get(trace)
        if breaks is not None:
            breaks.plan_delete(actions, self.length, self.kinds)
        for breaks in self.trace_breaks.values():
            breaks.plan_delete(actions, self.length, self.kinds)
        return await actions.execute()

    def plan_enable(self, actions: Any, trace: Any) -> None:
        if trace is not None:
            breaks = self.trace_breaks.get(trace)
            if breaks is not None:
                breaks.plan_enable(actions, self.length, self.kinds)
        for breaks in self.trace_breaks.values():
            breaks.plan_enable(actions, self.length, self.kinds)

    def plan_disable(self, actions: Any, trace: Any) -> None:
        if trace is not None:
            breaks = self.trace_breaks.get(trace)
            if breaks is not None:
                breaks.plan_disable(actions, self.length, self.kinds)
        for breaks in self.trace_breaks.values():
            breaks.plan_disable(actions, self.length, self.kinds)

    def plan_delete(self, actions: Any, trace: Any) -> None:
        if trace is not None:
            breaks = self.trace_breaks.get(trace)
            if breaks is not None:
                breaks.plan_delete(actions, self.length, self.kinds)
        for breaks in self.trace_breaks.values():
            breaks.plan_delete(actions, self.length, self.kinds)

    def get_program_bookmark(self) -> Any:
        return self.prog_break.get_bookmark()

    def get_program_location(self) -> Any:
        return self.prog_break.get_location()

    def set_trace_address(self, recorder: Any, address: int):
        self.trace_breaks[recorder] = TraceBreakpointSet(recorder, address)

    @property
    def trace_breakpoints(self) -> Set[Any]:
        result = set()
        for breaks in self.trace_breaks.values():
            result.update(breaks.get_breakpoints())
        return result

    @property
    def mapped_traces(self) -> Set[Any]:
        return frozenset(self.trace_breaks.keys())

    @property
    def participating_traces(self) -> Set[Any]:
        result = set()
        for breaks in self.trace_breaks.values():
            if not breaks.is_empty():
                result.add(breaks.get_trace())
        return result

    def get_trace_address(self, trace: Any):
        breaks = self.trace_breaks.get(trace)
        if breaks is None:
            return None
        return breaks.get_address()

    @property
    def domain_object(self) -> Any:
        return self.prog_break.get_program()

    @property
    def address(self) -> int:
        return self.prog_break.get_location().get_byte_address()

    @property
    def length_(self):
        return self.length

    @property
    def kinds_(self):
        return self.kinds

    def compute_enablement_for_program(self, program: Any) -> Any:
        if self.prog_break.get_program() != program:
            return Enablement.NONE
        return self.compute_enablement()

    def compute_enablement_for_trace(self, trace: Any) -> Any:
        breaks = self.trace_breaks.get(trace)
        prog_en = self.prog_break.compute_enablement()
        if breaks is None:
            return TraceEnablement.MISSING.combine_program(prog_en)
        # NB: Order matters. Trace is primary
        return breaks.compute_enablement().combine_program(prog_en)

    def compute_enablement(self) -> Any:
        prog_en = self.prog_break.compute_enablement()
        trace_en = TraceEnablement.NONE
        for breaks in self.trace_breaks.values():
            t_en = breaks.compute_enablement()
            trace_en = trace_en.combine(t_en)
            if trace_en == TraceEnablement.MIXED:
                break
        return prog_en.combine_trace(trace_en)

    def can_merge(self, program: Any, bookmark: Any) -> bool:
        return self.prog_break.can_merge(program, bookmark)

    def can_merge(self, breakpoint: Any):
        breaks = self.trace_breaks.get(breakpoint.get_trace())
        if breaks is None:
            raise AssertionError()
        if self.length_ != breakpoint.get_length():
            return False
        if not set(self.kinds_) == set(breakpoint.get_kinds()):
            return False
        return breaks.can_merge(breakpoint)

    def track_breakpoint(self, bookmark: Any) -> bool:
        return self.prog_break.add(bookmark)

    def track_breakpoint(self, breakpoint: Any):
        breaks = self.trace_breaks.get(breakpoint.get_trace())
        if breaks is None:
            raise AssertionError()
        return breaks.add(breakpoint)

    def untrack_breakpoint(self, program: Any, bookmark: Any) -> bool:
        assert self.prog_break.get_program() == program
        return self.prog_break.remove(bookmark)

    def untrack_breakpoint(self, breakpoint: Any):
        breaks = self.trace_breaks.get(breakpoint.get_trace())
        if breaks is None:
            raise AssertionError()
        return breaks.remove(breakpoint)
```

Note that Python does not have direct equivalent of Java's `Set` and `Map`. Instead, you can use built-in types like `set`, `dict`, or third-party libraries.