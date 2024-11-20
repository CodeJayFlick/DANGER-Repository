class LldbBreakpointConditionChangedEvent:
    def __init__(self, info):
        self._bkpt_info = info

    @property
    def breakpoint_info(self):
        return self._bkpt_info


# Example usage:
class DebugBreakpointInfo:
    pass  # This is a placeholder for the actual class definition in Java.


def main():
    debug_breakpoint_info = DebugBreakpointInfo()  # Replace with actual instance creation.
    event = LldbBreakpointConditionChangedEvent(debug_breakpoint_info)
    breakpoint_info = event.breakpoint_info
    print(breakpoint_info)  # This will print the breakpoint information


if __name__ == "__main__":
    main()
