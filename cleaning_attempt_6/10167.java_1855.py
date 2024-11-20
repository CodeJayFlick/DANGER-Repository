from typing import TypeVar, Any

I = TypeVar('I')

class QProgressListener:
    def progress_changed(self, id: int, item: I, current_progress: int) -> None:
        pass  # Implement this method in your subclass

    def task_started(self, id: int, item: I) -> None:
        pass  # Implement this method in your subclass

    def task_ended(self, id: int, item: I, total_count: int, completed_count: int) -> None:
        pass  # Implement this method in your subclass

    def progress_mode_changed(self, id: int, item: I, indeterminate: bool) -> None:
        pass  # Implement this method in your subclass

    def progress_message_changed(self, id: int, item: I, message: str) -> None:
        pass  # Implement this method in your subclass

    def max_progress_changed(self, id: int, item: I, max_progress: int) -> None:
        pass  # Implement this method in your subclass
