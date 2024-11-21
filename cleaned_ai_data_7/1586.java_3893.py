class LldbBreakpointHitEvent:
    def __init__(self, info):
        self.info = info

# Note: In Python, we don't need a separate class for DebugProcessInfo
debug_process_info = object  # or any other suitable placeholder

LldbBreakpointHitEvent(debug_process_info)
