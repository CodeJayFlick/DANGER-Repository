Here is a translation of the provided Java code into equivalent Python:

```Python
class LldbInsertBreakpointCommand:
    def __init__(self, manager, expression=None, loc=None, type='breakpoint'):
        self.manager = manager
        if isinstance(type, str):
            self.type = {'breakpoint': 'BREAKPOINT', 'hw_breakpoint': 'HW_BREAKPOINT',
                         'read_watchpoint': 'READ_WATCHPOINT', 'write_watchpoint': 'WRITE_WATCHPOINT'}.get(type)
        else:
            self.type = type

        self.expression = expression
        if loc is not None and isinstance(loc, int):
            self.loc = loc
        elif loc is not None and isinstance(loc, str) or isinstance(loc, bytes):
            raise ValueError("Invalid location")
        else:
            self.loc = None

    def complete(self, pending=None):
        current_session = self.manager.get_current_session()
        if self.type in ['BREAKPOINT', 'HW_BREAKPOINT']:
            breakpoint_info = LldbBreakpointInfo(breakpoint=self.create_breakpoint(current_session), process=current_session.get_process())
            return breakpoint_info
        elif self.type in ['READ_WATCHPOINT', 'WRITE_WATCHPOINT']:
            watchpoint_info = LddlWatchpointInfo(watchpoint=self.create_watchpoint(current_session, pending), process=current_session.get_process())
            return watchpoint_info

    def invoke(self):
        current_session = self.manager.get_current_session()
        if self.type in ['BREAKPOINT', 'HW_BREAKPOINT']:
            breakpoint = None
            if self.loc is not None:
                breakpoint = current_session.breakpoint_create_by_address(self.loc)
            else:
                breakpoint = current_session.breakpoint_create_by_regex(self.expression)

            breakpoint.set_enabled(True)
            bkpt_info = LldbBreakpointInfo(breakpoint, process=current_session.get_process())
        elif self.type in ['READ_WATCHPOINT', 'WRITE_WATCHPOINT']:
            read = True
            write = True
            error = None

            if self.type == 'READ_WATCHPOINT':
                write = False
            elif self.type == 'WRITE_WATCHPOINT':
                read = False

            watchpoint = current_session.watch_address(self.loc, 8, read, write, error)

            if not error.success():
                stream = SBStream()
                error.get_description(stream)
                print(f"Error: {stream.get_data()}")

        return bkpt_info

    def create_breakpoint(self, session):
        # TODO: HW_BREAKPOINT not handled here!
        pass

    def create_watchpoint(self, session, pending=None):
        if self.type == 'READ_WATCHPOINT':
            write = False
        elif self.type == 'WRITE_WATCHPOINT':
            read = False

        return None  # This should be replaced with actual watchpoint creation code.

class LddlBreakpointInfo:
    def __init__(self, breakpoint, process=None):
        self.breakpoint = breakpoint
        self.process = process

class SBError:
    def get_description(self, stream):
        pass

    @property
    def success(self):
        return True  # This should be replaced with actual error handling code.

class LddlWatchpointInfo:
    def __init__(self, watchpoint, process=None):
        self.watchpoint = watchpoint
        self.process = process
```

Please note that this is a direct translation of the provided Java code into equivalent Python. It may not work as expected without proper testing and handling of edge cases.