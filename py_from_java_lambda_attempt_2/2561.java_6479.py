Here is the translation of the Java interface `TraceStaticMapping` into a Python class:

```Python
class TraceStaticMapping:
    def __init__(self):
        pass  # No equivalent constructor in Java; no need for one here either.

    def get_trace(self) -> 'trace':
        """Get the "from" trace, i.e., the trace containing this mapping"""
        raise NotImplementedError

    def get_trace_address_range(self) -> tuple:
        """Get the "from" range"""
        raise NotImplementedError

    def get_min_trace_address(self) -> int:
        """Get the "from" range's minimum address"""
        raise NotImplementedError

    def get_max_trace_address(self) -> int:
        """Get the "from" range's maximum address"""
        raise NotImplementedError

    # TODO: Lifespan, start/end snap setters? (no equivalent in Python)

    def get_length(self) -> int:
        """Get the length of the mapping, i.e., the length of the range"""
        raise NotImplementedError

    def get_shift(self) -> int:
        """Get the shift in offset from static program to dynamic trace"""
        raise NotImplementedError

    # TODO: Lifespan setter? (no equivalent in Python)

    def get_lifespan(self) -> tuple:
        """Get the span of time of the mapping"""
        raise NotImplementedError

    def get_start_snap(self) -> int:
        """Get the starting snap of the lifespan"""
        raise NotImplementedError

    def get_end_snap(self) -> int:
        """Get the ending snap of the lifespan"""
        raise NotImplementedError

    # TODO: Static program URL setter? (no equivalent in Python)

    def get_static_program_url(self) -> str:
        """Get the Ghidra URL of the "to" Program, i.e., static image"""
        raise NotImplementedError

    def get_static_address(self) -> str:
        """Get the "to" address range's minimum address, as a string"""
        raise NotImplementedError

    # TODO: Lifespan setter? (no equivalent in Python)

    def delete(self):
        """Remove this mapping from the "from" trace"""
        pass  # No need for any action here.

    def conflicts_with(self, range: tuple, lifespan: tuple, to_program_url: str, 
                       to_address: str) -> bool:
        """Check if this mapping would conflict with the given prospective mapping"""
        raise NotImplementedError
```

This Python class does not contain a direct equivalent of Java's `extends TraceObject` because there is no built-in way in Python for classes to inherit from interfaces.