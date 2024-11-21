import threading

class Job:
    def __init__(self):
        self._completed = False
        self._cancelled = False
        self._error = None
        self._task_monitor = None

    @property
    def completed(self):
        return self._completed

    @completed.setter
    def set_completed(self, value=True):
        self._completed = value

    @property
    def cancelled(self):
        return self._cancelled

    @cancelled.setter
    def cancel(self):
        self._cancelled = True
        if self._task_monitor:
            self._task_monitor.cancel()

    @property
    def has_error(self):
        return self._error is not None

    @has_error.setter
    def set_error(self, error=None):
        self._error = error

    @property
    def get_error(self):
        return self._error

    def run(self, task_monitor):
        raise NotImplementedError("Subclasses must implement this method")

    def set_task_monitor(self, monitor):
        self._task_monitor = monitor
