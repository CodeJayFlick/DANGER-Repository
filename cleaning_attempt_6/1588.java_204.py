class LldbBreakpointInvalidatedEvent:
    def __init__(self, info):
        self._bkpt_info = info

    @property
    def breakpoint_info(self):
        return self._bkpt_info


# Example usage:
class DebugBreakpointInfo:
    pass  # This is a placeholder for the actual class in Java. In Python, we don't need this class definition.

info = DebugBreakpointInfo()  # Create an instance of the info
event = LldbBreakpointInvalidatedEvent(info)  # Create an event with the given breakpoint information

print(event.breakpoint_info)
