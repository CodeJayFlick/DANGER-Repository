class LldbBreakpointEnabledEvent:
    def __init__(self, info):
        self.bkpt_info = info

    def get_breakpoint_info(self):
        return self.bkpt_info


# Note: In Python, we don't have a direct equivalent of Java's generics. So the type parameter 'DebugBreakpointInfo' is not included in the class definition.
