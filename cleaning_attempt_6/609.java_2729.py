class DbgDeleteBreakpointsCommand:
    def __init__(self, manager, numbers):
        self.manager = manager
        self.numbers = numbers

    def invoke(self):
        control = self.manager.get_control()
        for id in self.numbers:
            self.manager.do_breakpoint_deleted(id, 'UNCLAIMED')
            bp = control.get_breakpoint_by_id(int(id))
            if bp is not None:
                bp.remove()

# Example usage
class DbgManagerImpl:
    def get_control(self):
        # implementation of this method goes here
        pass

    def do_breakpoint_deleted(self, id, cause):
        # implementation of this method goes here
        pass


manager = DbgManagerImpl()
numbers = [1, 2, 3]
command = DbgDeleteBreakpointsCommand(manager, numbers)
command.invoke()
