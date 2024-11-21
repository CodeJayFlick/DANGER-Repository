class LldbEnableBreakpointsCommand:
    def __init__(self, manager, *ids):
        self.manager = manager
        self.ids = ids

    def complete(self, pending=None):
        current_session = self.manager.get_current_session()
        for id in self.ids:
            self.manager.do_breakpoint_enabled(current_session, id, pending)
        return None

    def invoke(self):
        known_breakpoints = self.manager.get_known_breakpoints(self.manager.get_current_session())
        for id in self.ids:
            if id in known_breakpoints:
                obj = known_breakpoints[id]
                if isinstance(obj, SBBreakpoint):
                    obj.set_enabled(True)
                elif isinstance(obj, SBWatchpoint):
                    obj.set_enabled(True)

class LldbManagerImpl:
    def get_current_session(self):
        # implementation of this method
        pass

    def do_breakpoint_enabled(self, session, id, pending=None):
        # implementation of this method
        pass

    def get_known_breakpoints(self, session):
        # implementation of this method
        pass
