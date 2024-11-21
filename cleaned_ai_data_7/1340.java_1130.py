class GdbDisableBreakpointsCommand:
    def __init__(self, manager, numbers):
        self.manager = manager
        self.numbers = numbers

    def encode(self):
        return f"-break-disable {' '.join(map(str, self.numbers))}"

    def handle(self, evt, pending):
        if super().handle(evt, pending):
            return True
        
        if isinstance(evt, GdbBreakpointModifiedEvent):
            pending.claim(evt)
        
        return False

    def complete(self, pending):
        pending.check_completion(GdbCommandDoneEvent)
        for number in self.numbers:
            self.manager.do_breakpoint_disabled(number, pending)
        return None
