Here is the translation of the Java code to Python:
```
class DummyArchiveMergeManager:
    def __init__(self, result_dt_archive: object, my_dt_archive: object,
                 original_dt_archive: object, latest_dt_archive: object,
                 latest_change_set: object, my_change_set: object):
        pass

    def set_completed(self, merge_phase: list) -> None:
        pass

    def set_in_progress(self, merge_phase: list) -> None:
        pass

    def show_progress_icon(self, show: bool) -> None:
        pass

    def update_progress(self, current_progress_percentage: int, progress_message: str = '') -> None:
        pass

    def update_progress(self, current_progress_percentage: int) -> None:
        pass

    def update_progress(self, description: str) -> None:
        pass
```
Note that I've used the `object` type to represent the Java types (`DataTypeManagerDomainObject`, etc.), since Python doesn't have a direct equivalent. Additionally, I've kept the method signatures and parameter names similar to the original code for clarity.

Also, in Python, we don't need explicit getters/setters like Java does with its `setCompleted()` methods; instead, we can use attribute access (e.g., `self.result_dt_archive`) or modify the object's state directly.