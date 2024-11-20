Here is a translation of the Java interface into equivalent Python classes:

```Python
class LldbEventsListenerAdapter:
    def session_added(self, session: 'SBTarget', cause: str) -> None:
        # Extension point
        pass

    def session_replaced(self, session: 'SBTarget', cause: str) -> None:
        # Extension point
        pass

    def session_removed(self, session_id: str, cause: str) -> None:
        # Extension point
        pass

    def session_selected(self, session: 'SBTarget', cause: str) -> None:
        # Extension point
        pass

    def process_added(self, process: 'SBProcess', cause: str) -> None:
        # Extension point
        pass

    def process_replaced(self, process: 'SBProcess', cause: str) -> None:
        # Extension point
        pass

    def process_removed(self, process_id: str, cause: str) -> None:
        # Extension point
        pass

    def process_selected(self, process: 'SBProcess', cause: str) -> None:
        # Extension point
        pass

    def process_started(self, process: 'SBProcess', cause: str) -> None:
        # Extension point
        pass

    def process_exited(self, process: 'SBProcess', cause: str) -> None:
        # Extension point
        pass

    def thread_created(self, thread: 'SBThread', cause: str) -> None:
        # Extension point
        pass

    def thread_replaced(self, thread: 'SBThread', cause: str) -> None:
        # Extension point
        pass

    def thread_state_changed(self, thread: 'SBThread', state: int, cause: str, reason: str) -> None:
        # Extension point
        pass

    def thread_exited(self, thread: 'SBThread', process: 'SBProcess', cause: str) -> None:
        # Extension point
        pass

    def thread_selected(self, thread: 'SBThread', frame: int, cause: str) -> None:
        # Extension point
        pass

    def module_loaded(self, process: 'SBProcess', info: dict, index: int, cause: str) -> None:
        # Extension point
        pass

    def module_unloaded(self, process: 'SBProcess', info: dict, index: int, cause: str) -> None:
        # Extension point
        pass

    def breakpoint_created(self, info: object, cause: str) -> None:
        # Extension point
        pass

    def breakpoint_modified(self, info: object, cause: str) -> None:
        # Extension point
        pass

    def breakpoint_deleted(self, info: object, cause: str) -> None:
        # Extension point
        pass

    def breakpoint_hit(self, info: object, cause: str) -> None:
        # Extension point
        pass

    def memory_changed(self, process: 'SBProcess', addr: int, len: int, cause: str) -> None:
        # Extension point
        pass

    def console_output(self, output: str, mask: int) -> None:
        # Extension point
        pass

    def prompt_changed(self, prompt: str) -> None:
        # Extension point
        pass
```

Note that Python does not have a direct equivalent to Java's `default` keyword. In this translation, I've omitted the `default` keywords and simply provided empty function bodies for each method in the interface.