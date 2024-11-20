Here is the translation of the given Java code into Python:

```Python
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
```

Please note that the Python code is a direct translation and does not include any error handling or exception checking. Also, some methods like `get_control()`, `do_breakpoint_deleted()` are placeholders for actual implementation in your application.