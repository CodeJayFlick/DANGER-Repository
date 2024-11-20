Here is the equivalent Python code:

```
class LldbBreakpointType:
    BREAKPOINT = 'BREAKPOINT'
    HW_BREAKPOINT = 'HW_BREAKPOINT'
    WRITE_WATCHPOINT = 'WRITE_WATCHPOINT'
    READ_WATCHPOINT = 'READ_WATCHPOINT'
    ACCESS_WATCHPOINT = 'ACCESS_WATCHPOINT'
    OTHER = 'OTHER'

    @classmethod
    def from_str(cls, string):
        try:
            return getattr(LldbBreakpointType, string)
        except AttributeError:
            return LldbBreakpointType.OTHER

```

Note that Python does not have an exact equivalent to Java's enum type. Instead, we define a class with static variables for each breakpoint type. The `from_str` method is similar to the original Java code, but uses Python's built-in `getattr` function instead of trying to create an instance from a string.