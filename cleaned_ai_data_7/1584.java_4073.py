class LldbBreakpointDisabledEvent:
    def __init__(self, info):
        self.bkpt_info = info

    def get_breakpoint_info(self):
        return self.bkpt_info


# Define a class for DebugBreakpointInfo (assuming it's not available in the standard library)
class DebugBreakpointInfo:
    pass
