Here's your Java code translated into Python:

```Python
class LogicalBreakpoint:
    BREAKPOINT_ENABLED_BOOKMARK_TYPE = "BreakpointEnabled"
    BREAKPOINT_DISABLED_BOOKMARK_TYPE = "BreakpointDisabled"

    class ProgramEnablement(enum.Enum):
        NONE = 0
        MISSING = 1
        ENABLED = 2
        DISABLED = 3

        def combine_trace(self, trace_en: 'LogicalBreakpoint.TraceEnablement') -> 'LogicalBreakpoint.Enablement':
            if self == LogicalBreakpoint.ProgramEnablement.NONE:
                return LogicalBreakpoint.Enablement.NEFFECTIVE_DISABLED
            elif self == LogicalBreakpoint.ProgramEnablement.MISSING:
                return LogicalBreakpoint.Enablement.NEFFECTIVE_ENABLED
            else:
                return trace_en.combine_program(self)

        def combine_program(self, prog_en: 'LogicalBreakpoint.TraceEnablement') -> 'LogicalBreakpoint.Enablement':
            if self == LogicalBreakpoint.ProgramEnablement.NONE or self == LogicalBreakpoint.ProgramEnablement.MISSING:
                return LogicalBreakpoint.Enablement.NEFFECTIVE_DISABLED
            elif self == LogicalBreakpoint.ProgramEnablement.ENABLED:
                return LogicalBreakpoint.Enablement.DISABLED_ENABLED
            else:
                return prog_en

    class TraceEnablement(enum.Enum):
        NONE = 0
        MISSING = 1
        ENABLED = 2
        DISABLED = 3
        MIXED = 4

        def combine(self, that: 'LogicalBreakpoint.TraceEnablement') -> 'LogicalBreakpoint.TraceEnablement':
            if self == LogicalBreakpoint.TraceEnablement.NONE:
                return that
            elif that == LogicalBreakpoint.TraceEnablement.NONE:
                return self
            else:
                return LogicalBreakpoint.TraceEnablement.MIXED

        def combine_program(self, prog_en: 'LogicalBreakpoint.ProgramEnablement') -> 'LogicalBreakport.Enablement':
            if self == LogicalBreakpoint.TraceEnablement.NE:
                return prog_en.combine_program(self)

    class Enablement(enum.Enum):
        NONE = 0
        ENABLED = 1
        DISABLED = 2

        def __init__(self, enabled: bool, disabled: bool, consistent: bool, effective: bool):
            self.enabled = enabled
            self.disabled = disabled
            self.consistent = consistent
            self.effective = effective

    def same_address(self) -> 'LogicalBreakpoint.Enablement':
        if not self.effective:
            return LogicalBreakport.Enablement.NEFFECTIVE_ENABLED if self.enabled else LogicalBreakport.Enablement.NEFFECTIVE_DISABLED
        elif self.enabled and self.disabled:
            return LogicalBreakport.Enablement.ENABLED_DISABLED
        else:
            return LogicalBreakport.Enablement.DISABLED

    def get_primary(self) -> 'LogicalBreakpoint.Enablement':
        # This is an abstract method, you should implement it in your subclass.
        pass

class DomainObject:
    pass

class ProgramLocation:
    def __init__(self):
        self.program = None

class Bookmark:
    pass

class TraceBreakpointKind(enum.Enum):
    pass

class LogicalBreakpoint(DomainObject):
    def __init__(self, program_location: 'ProgramLocation', trace_breakpoints: set['TraceBreakpoint']):
        # Initialize your logical breakpoint here.
        pass

    def compute_enablement_for_program(self) -> 'LogicalBreakport.Enablement':
        if self.program_location is None:
            return LogicalBreakport.Enablement.NEFFECTIVE_DISABLED
        else:
            return LogicalBreakport.Enablement.ENABLED

    def enable_for_trace(self, trace: 'Trace') -> CompletableFuture['Void']:
        # This method should be implemented in your subclass.
        pass

    def disable_for_trace(self, trace: 'Trace') -> CompletableFuture['Void']:
        # This method should be implemented in your subclass.
        pass

    def delete_for_trace(self, trace: 'Trace') -> CompletableFuture['Void']:
        # This method should be implemented in your subclass.
        pass
```

This is a direct translation of the Java code into Python. Note that some methods and classes are not fully implemented as they were abstract or had no implementation in the original Java code.