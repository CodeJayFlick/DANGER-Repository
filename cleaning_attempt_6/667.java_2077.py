class DbgEventsListener:
    def session_added(self, session: 'DbgSession', cause: 'DbgCause'):
        pass  # Implement your logic here

    def session_removed(self, session_id: int, cause: 'DbgCause'):
        pass  # Implement your logic here

    def session_selected(self, session: 'DbgSession', cause: 'DbgCause'):
        pass  # Implement your logic here

    def process_added(self, process: 'DbgProcess', cause: 'DbgCause'):
        pass  # Implement your logic here

    def process_removed(self, process_id: int, cause: 'DbgCause'):
        pass  # Implement your logic here

    def process_selected(self, process: 'DbgProcess', frame: 'DbgStackFrame', cause: 'DbgCause'):
        pass  # Implement your logic here

    def process_started(self, process: 'DbgProcess', cause: 'DbgCause'):
        pass  # Implement your logic here

    def process_exited(self, process: 'DbgProcess', cause: 'DbgCause'):
        pass  # Implement your logic here

    def thread_created(self, thread: 'DbgThread', cause: 'DbgCause'):
        pass  # Implement your logic here

    def thread_state_changed(self, thread: 'DbgThread', state: int, cause: 'DbgCause', reason: int):
        pass  # Implement your logic here

    def thread_exited(self, thread_id: int, process: 'DbgProcess', cause: 'DbgCause'):
        pass  # Implement your logic here

    def thread_selected(self, thread: 'DbgThread', frame: 'DbgStackFrame', cause: 'DbgCause'):
        pass  # Implement your logic here

    def event_selected(self, event: 'AbstractDbgEvent[object]', cause: 'DbgCause'):
        pass  # Implement your logic here

    def module_loaded(self, process: 'DbgProcess', info: 'DebugModuleInfo', cause: 'DbgCause'):
        pass  # Implement your logic here

    def module_unloaded(self, process: 'DbgProcess', info: 'DebugModuleInfo', cause: 'DbgCause'):
        pass  # Implement your logic here

    def breakpoint_created(self, info: 'DbgBreakpointInfo', cause: 'DbgCause'):
        pass  # Implement your logic here

    def breakpoint_modified(self, new_info: 'DbgBreakpointInfo', old_info: 'DbgBreakpointInfo', cause: 'DbgCause'):
        pass  # Implement your logic here

    def breakpoint_deleted(self, info: 'DbgBreakpointInfo', cause: 'DbgCause'):
        pass  # Implement your logic here

    def breakpoint_hit(self, info: 'DbgBreakpointInfo', cause: 'DbgCause'):
        pass  # Implement your logic here

    def memory_changed(self, process: 'DbgProcess', addr: int, len: int, cause: 'DbgCause'):
        pass  # Implement your logic here

    def console_output(self, output: str, mask: int):
        pass  # Implement your logic here

    def prompt_changed(self, prompt: str):
        pass  # Implement your logic here
