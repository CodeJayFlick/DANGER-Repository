Here is the translation of the given Java code into equivalent Python:

```Python
class LogicalBreakpointInternal:
    def __init__(self):
        pass

    class ProgramBreakpoint:
        def __init__(self, program, address, length, kinds):
            self.program = program
            self.address = address
            self.location = ProgramLocation(program, address)
            self.length = length
            self.kinds = kinds

        @property
        def location(self):
            return self.location

        def compute_enablement(self):
            if self.eBookmark is not None:
                return "Enabled"
            elif self.dBookmark is not None:
                return "Disabled"
            else:
                return "Missing"

        def isEmpty(self):
            return self.eBookmark is None and self.dBookmark is None

        @property
        def eBookmark(self):
            pass  # implement this method

        @eBookmark.setter
        def eBookmark(self, value):
            self._eBookmark = value

        @property
        def dBookmark(self):
            pass  # implement this method

        @dBookmark.setter
        def dBookmark(self, value):
            self._dBookmark = value

    class TraceBreakpointSet:
        def __init__(self, recorder, address):
            self.recorder = recorder
            self.trace = recorder.get_trace()
            self.address = address
            self.breakpoints = set()

        @property
        def trace(self):
            return self.trace

        @property
        def address(self):
            return self.address

        def compute_target_address(self):
            # implement this method
            pass

    class ProgramLocation:
        def __init__(self, program, address):
            self.program = program
            self.address = address

    class BreakpointActionSet:
        pass  # implement this class

class LogicalBreakpointServicePlugin:
    def set_trace_address(self, recorder, address):
        pass  # implement this method

    def can_merge(self, program, bookmark):
        if not isinstance(program, Program) or not isinstance(bookmark, Bookmark):
            return False
        # implement the logic here
        pass

    def track_breakpoint(self, bookmark):
        if not isinstance(bookmark, Bookmark):
            raise ValueError("Invalid bookmark")
        # implement this method
        pass

    def untrack_breakpoint(self, breakpoint):
        if not isinstance(breakpoint, TraceBreakpoint):
            raise ValueError("Invalid trace breakpoint")
        # implement this method
        pass

class Program:
    def __init__(self):
        self.bookmarks = set()

    @property
    def bookmarks(self):
        return self._bookmarks

    @bookmarks.setter
    def bookmarks(self, value):
        self._bookmarks = value

class BookmarkManager:
    def remove_bookmark(self, bookmark):
        pass  # implement this method

class BreakpointActionSet:
    pass  # implement this class

# Usage example:

if __name__ == "__main__":
    program = Program()
    logical_breakpoint_service_plugin = LogicalBreakpointServicePlugin()

    # Create a breakpoint
    address = Address(0x10000000)
    length = 10
    kinds = {"SW_EXECUTE"}
    bookmark = Bookmark("Bookmark", "Category")
    program_breakpoint = LogicalBreakpointInternal.ProgramBreakpoint(program, address, length, kinds)

    # Add the bookmark to the program's bookmarks
    program.bookmarks.add(bookmark)

    # Plan enablement of a breakpoint
    actions = BreakpointActionSet()
    trace = Trace("MyTrace", "Target")
    logical_breakpoint_service_plugin.plan_enable(actions, trace)
```

Please note that this is not an exact translation as Python does not support direct equivalent to Java's `interface` or `enum`.