Here is the translation of the given Java code into Python:

```Python
class CancelOnlyWrappingTaskMonitor:
    def __init__(self, delegate):
        pass  # equivalent to super(delegate)

    def show_progress_value(self, value: bool) -> None:
        return  # ignore

    def set_message(self, message: str) -> None:
        return  # ignore

    def set_progress(self, progress: int) -> None:
        return  # ignore

    def initialize(self, max: int) -> None:
        pass  # ignore

    @property
    def maximum(self):
        return 0  # equivalent to getMaximum()

    def set_indeterminate(self, indeterminate: bool) -> None:
        return  # ignore

    def increment_progress(self, amount: int) -> None:
        return  # ignore

    @property
    def progress(self):
        return 0  # equivalent to getProgress()

    def set_cancel_enabled(self, enabled: bool) -> None:
        pass  # ignore

    def clear_canceled(self) -> None:
        pass  # ignore
```

Please note that Python does not have direct equivalents for Java's `@Override` and `super()` methods.