Here is the translation of the given Java code into equivalent Python:

```Python
class LldbBreakpointIgnoreChangedEvent:
    def __init__(self, info):
        self._bkpt_info = info

    @property
    def breakpoint_info(self):
        return self._bkpt_info


# Example usage:
class DebugBreakpointInfo:
    pass  # This is a placeholder for the actual class definition in Java.


event = LldbBreakpointIgnoreChangedEvent(DebugBreakpointInfo())
print(event.breakpoint_info)
```

Please note that this Python code does not exactly replicate the given Java code. The `DebugBreakpointInfo` class and its methods are placeholders, as they do not have direct equivalents in Python.