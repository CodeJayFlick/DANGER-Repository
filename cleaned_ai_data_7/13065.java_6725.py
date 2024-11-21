class TaskMonitor:
    DUMMY = DummyTaskMonitor()

    def __init__(self):
        self._cancelled = False
        self._progress_value = -1
        self._max_progress_value = 0
        self._indeterminate = False

    @classmethod
    def dummy_if_null(cls, tm):
        return tm if tm is not None else cls.DUMMY

    def is_cancelled(self) -> bool:
        return self._cancelled

    def set_show_progress_value(self, show_progress: bool):
        pass  # No equivalent in Python

    def set_message(self, message: str):
        pass  # No equivalent in Python

    def get_message(self) -> str:
        raise NotImplementedError("Method not implemented")

    def set_progress(self, value: int):
        self._progress_value = value
        if self._max_progress_value > 0 and value >= self._max_progress_value:
            self._progress_value = self._max_progress_value

    def get_progress(self) -> int:
        return self._progress_value

    def initialize(self, max: int):
        self._progress_value = 0
        self._max_progress_value = max

    def set_maximum(self, value: int):
        if self._progress_value > value:
            self._progress_value = value
        self._max_progress_value = value

    def get_maximum(self) -> int:
        return self._max_progress_value

    def set_indeterminate(self, indeterminate: bool):
        self._indeterminate = indeterminate

    def is_indeterminate(self) -> bool:
        return self._indeterminate

    def check_cancelled(self):
        if self.is_cancelled():
            raise CancelledException("Task cancelled")

    def increment_progress(self, amount: int):
        self.set_progress(self.get_progress() + amount)

    def cancel(self):
        self._cancelled = True
