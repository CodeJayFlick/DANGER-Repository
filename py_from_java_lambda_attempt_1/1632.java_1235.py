Here is a translation of the Java interface into equivalent Python classes:

```Python
class LldbEventsListener:
    def session_added(self, session: 'SBTarget', cause: str):
        pass  # TODO implement this method

    def session_replaced(self, session: 'SBTarget', cause: str):
        pass  # TODO implement this method

    def session_removed(self, session_id: str, cause: str):
        pass  # TODO implement this method

    def session_selected(self, session: 'SBTarget', cause: str):
        pass  # TODO implement this method

    def process_added(self, process: 'SBProcess', cause: str):
        pass  # TODO implement this method

    def process_replaced(self, process: 'SBProcess', cause: str):
        pass  # TODO implement this method

    def process_removed(self, process_id: str, cause: str):
        pass  # TODO implement this method

    def process_selected(self, process: 'SBProcess', cause: str):
        pass  # TODO implement this method

    def process_started(self, process: 'SBProcess', cause: str):
        pass  # TODO implement this method

    def process_exited(self, process: 'SBProcess', cause: str):
        pass  # TODO implement this method

    def thread_created(self, thread: 'SBThread', cause: str):
        pass  # TODO implement this method

    def thread_replaced(self, thread: 'SBThread', cause: str):
        pass  # TODO implement this method

    def thread_state_changed(self, thread: 'SBThread', state: int, cause: str, reason: str):
        pass  # TODO implement this method

    def thread_exited(self, thread_id: str, process: 'SBProcess', cause: str):
        pass  # TODO implement this method

    def thread_selected(self, thread: 'SBThread', frame: 'SBFrame', cause: str):
        pass  # TODO implement this method

    def module_loaded(self, process: 'SBProcess', info: dict, index: int, cause: str):
        pass  # TODO implement this method

    def module_unloaded(self, process: 'SBProcess', info: dict, index: int, cause: str):
        pass  # TODO implement this method

    def breakpoint_created(self, info: dict, cause: str):
        pass  # TODO implement this method

    def breakpoint_modified(self, new_info: dict, old_info: dict, cause: str):
        pass  # TODO implement this method

    def breakpoint_deleted(self, info: dict, cause: str):
        pass  # TODO implement this method

    def breakpoint_hit(self, info: dict, cause: str):
        pass  # TODO implement this method

    def memory_changed(self, process: 'SBProcess', addr: int, len: int, cause: str):
        pass  # TODO implement this method

    def console_output(self, output: str, mask: int):
        pass  # TODO implement this method

    def prompt_changed(self, prompt: str):
        pass  # TODO implement this method
```

Please note that Python does not support Java's `interface` keyword. Instead, we can define a class with methods that are intended to be implemented by subclasses.

Also, the types of some parameters have been changed from their original Java types to equivalent Python types (e.g., `String` -> `str`, etc.).