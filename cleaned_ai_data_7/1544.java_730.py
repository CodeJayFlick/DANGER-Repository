class LldbDisableBreakpointsCommand:
    def __init__(self, manager, *ids):
        self.manager = manager
        self.ids = ids

    def complete(self, pending=None):
        current_session = self.manager.get_current_session()
        for id in self.ids:
            self.manager.do_breakpoint_disabled(current_session, id, pending)
        return None

    def invoke(self):
        known_breakpoints = self.manager.get_known_breakpoints(self.manager.get_current_session())
        for id in self.ids:
            if id in known_breakpoints:
                obj = known_breakpoints[id]
                if isinstance(obj, dict) and 'enabled' in obj:
                    obj['enabled'] = False
