Here is the translation of the Java code into Python:

```Python
class Task:
    def __init__(self, title: str):
        self.title = title
        self.has_progress = False
        self.is_modal = False
        self.can_cancel = True
        self.is_cancelled = False
        self.wait_for_task_completed = False

    def get_task_title(self) -> str:
        return self.title

    def set_has_progress(self, has_progress: bool):
        self.has_progress = has_progress

    def can_cancel(self) -> bool:
        return self.can_cancel

    def is_modal(self) -> bool:
        return self.is_modal

    def get_status_text_alignment(self) -> int:
        return SwingConstants.CENTER  # Assuming SwingConstants from a separate module

    def monitored_run(self, monitor):
        try:
            self.run(monitor)
            if monitor.is_cancelled():
                self.is_cancelled = True
        except CancelledException as e:
            print(f"Task cancelled: {self.title}")
            self.is_cancelled = True
        finally:
            TaskUtilities.remove_tracked_task(self)

    def cancel(self):
        pass  # Assuming a separate module for task monitor

    def is_cancelled(self) -> bool:
        return self.is_cancelled

    def notify_task_listeners(self, was_cancelled: bool):
        if not self.listeners:
            return
        r = lambda: [listener.task_completed(self) if not was_cancelled else listener.task_cancelled(self)
                     for listener in self.listeners]
        Swing.run_now(r)  # Assuming a separate module for swing

    def run(self, monitor):
        pass  # Abstract method to be implemented by subclasses


class TaskMonitor:
    DUMMY = None
```

Note that I've used Python's type hinting system (e.g., `-> str`) and the equivalent of Java's `abstract` keyword (`pass`).