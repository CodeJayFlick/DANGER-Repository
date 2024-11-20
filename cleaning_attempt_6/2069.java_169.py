from typing import List, Dict, Any

class JdiModelTargetThreadContainer:
    def __init__(self, object: Any, name: str, threads: List):
        self.object = object
        self.name = name
        self.threads = threads

    def thread_created(self, thread: Any) -> None:
        target_thread = self.get_target_thread(thread)
        self.change_elements([], [target_thread], {}, "Created")

    def thread_exited(self, thread: Any) -> None:
        with self.lock:
            if thread.name in self.threads_by_id:
                del self.threads_by_id[thread.name]
        self.change_elements([thread.name], [], {}, "Exited")

    def thread_state_changed(self, thread: Any, state: int, cause: str, reason: str) -> None:
        target_thread = self.get_target_thread(thread)
        target_state = target_thread.convert_state(state)
        target_thread.thread_state_changed(target_state)
        event_type = self.get_event_type(reason)
        self.fire_event(self, target_thread, event_type,
                         f"Thread {target_thread.name} state changed", [target_thread])

    def get_event_type(self, reason: str) -> Any:
        if reason == "STEP":
            return "STEP_COMPLETED"
        elif reason == "BREAKPOINT_HIT":
            return "BREAKPOINT_HIT"
        elif reason == "ACCESS_WATCHPOINT_HIT":
            return "BREAKPOINT_HIT"
        elif reason == "WATCHPOINT_HIT":
            return "BREAKPOINT_HIT"
        elif reason == "INTERRUPT":
            return "SIGNAL"
        elif reason == "RESUMED":
            return "RUNNING"
        else:
            return "STOPPED"

    def update_using_threads(self, refs: List) -> Any:
        target_threads = []
        with self.lock:
            for ref in refs:
                target_thread = self.get_target_thread(ref)
                if target_thread is not None:
                    target_threads.append(target_thread)

        fence = AsyncFence()
        for thread in target_threads:
            fence.include(thread.init())
        return fence.ready().then_accept(lambda x: self.set_elements(target_threads, {}, "Refreshed"))

    def request_elements(self, refresh: bool) -> Any:
        return self.update_using_threads(self.threads)

    @property
    def lock(self):
        if not hasattr(self, "_lock"):
            self._lock = threading.Lock()
        return self._lock

    def get_target_thread(self, thread: Any) -> None:
        return self.threads_by_id.get(thread.name)

    def get_target_thread_if_present(self, name: str) -> None:
        return self.threads_by_id.get(name)
