class DbgEnableBreakpointsCommand:
    def __init__(self, manager, *numbers):
        self.manager = manager
        self.numbers = numbers

    def invoke(self):
        control = self.manager.get_control()
        for num in self.numbers:
            bp = control.get_breakpoint_by_id(int(num))
            bp.add_flags("ENABLED")
