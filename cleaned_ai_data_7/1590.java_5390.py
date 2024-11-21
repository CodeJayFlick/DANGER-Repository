class LldbBreakpointLocationsRemovedEvent:
    def __init__(self, info):
        self.bkpt_info = info

    @property
    def breakpoint_info(self):
        return self.bkpt_info


# Example usage:
debug_breakpoint_info = {'some_key': 'some_value'}  # Replace with actual debug breakpoint information
event = LldbBreakpointLocationsRemovedEvent(debug_breakpoint_info)
print(event.breakpoint_info)  # Output: {'some_key': 'some_value'}
