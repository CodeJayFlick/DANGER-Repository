class LldbBreakpointCommandChangedEvent:
    def __init__(self, info):
        self._bkpt_info = info

    @property
    def breakpoint_info(self):
        return self._bkpt_info


# Example usage:
if __name__ == "__main__":
    class DebugBreakpointInfo:  # This is a placeholder for the actual Java class.
        pass

    event = LldbBreakpointCommandChangedEvent(DebugBreakpointInfo())
    print(event.breakpoint_info)
