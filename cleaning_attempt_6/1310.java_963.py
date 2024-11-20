class GdbEventsListener:
    def inferior_added(self, inferior: 'GdbInferior', cause: 'GdbCause'):
        pass  # implement this method as needed

    def inferior_removed(self, inferior_id: int, cause: 'GdbCause'):
        pass  # implement this method as needed

    def inferior_selected(self, inferior: 'GdbInferior', cause: 'GdbCause'):
        pass  # implement this method as needed

    def inferior_started(self, inferior: 'GdbInferior', cause: 'GdbCause'):
        pass  # implement this method as needed

    def inferior_exited(self, inferior: 'GdbInferior', cause: 'GdbCause'):
        pass  # implement this method as needed

    def inferior_state_changed(self, inf: 'GdbInferior', threads: list['GdbThread'], state: 'GdbState',
                                thread: 'GdbThread' = None,
                                cause: 'GdbCause' = None,
                                reason: 'GdbReason' = None):
        pass  # implement this method as needed

    def thread_created(self, thread: 'GdbThread', cause: 'GdbCause'):
        pass  # implement this method as needed

    def thread_state_changed(self, thread: 'GdbThread', state: 'GdbState',
                             cause: 'GdbCause' = None,
                             reason: 'GdbReason' = None):
        pass  # implement this method as needed

    def thread_exited(self, thread_id: int, inferior: 'GdbInferior', cause: 'GdbCause'):
        pass  # implement this method as needed

    def thread_selected(self, thread: 'GdbThread', frame: 'GdbStackFrame',
                        cause: 'GdbCause' = None):
        pass  # implement this method as needed

    def library_loaded(self, inferior: 'GdbInferior', name: str,
                       cause: 'GdbCause'):
        pass  # implement this method as needed

    def library_unloaded(self, inferior: 'GdbInferior', name: str,
                          cause: 'GdbCause'):
        pass  # implement this method as needed

    def breakpoint_created(self, info: 'GdbBreakpointInfo',
                           cause: 'GdbCause'):
        pass  # implement this method as needed

    def breakpoint_modified(self, new_info: 'GdbBreakpointInfo', old_info: 'GdbBreakpointInfo',
                            cause: 'GdbCause'):
        pass  # implement this method as needed

    def breakpoint_deleted(self, info: 'GdbBreakpointInfo', cause: 'GdbCause'):
        pass  # implement this method as needed

    def memory_changed(self, inferior: 'GdbInferior', addr: int,
                       len: int, cause: 'GdbCause'):
        pass  # implement this method as needed

    def param_changed(self, param: str, value: str, cause: 'GdbCause'):
        pass  # implement this method as needed
