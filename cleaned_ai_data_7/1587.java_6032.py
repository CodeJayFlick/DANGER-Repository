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
