Here is the translation of the given Java code into Python:

```Python
import time
from threading import Timer


class TimeoutTaskMonitor:
    def __init__(self, delegate, timeout, time_unit):
        self.delegate = Objects.requireNonNull(delegate)
        if not self.delegate.is_cancel_enabled():
            # could be a dummy monitor; create a monitor we can cancel
            self.delegate = TaskMonitorAdapter(True)

        self.timeout = timeout
        self.time_unit = time_unit

        millis = TimeUnit.MILLISECONDS.convert(timeout, time_unit)
        timer_monitor = Timer(millis / 1000.0, lambda: self._timeout())
        timer_monitor.start()

    def set_timeout_listener(self, callback):
        if not isinstance(callback, Callback):
            raise TypeError("Callback must be an instance of Callback")
        self.callback = callback

    @property
    def did_timeout(self):
        return self.did_time_out.get()

    def finished(self):
        self.callback = Dummy()

    # TaskMonitor Methods


class TaskMonitorAdapter:
    def __init__(self, cancel_enabled=True):
        self.cancel_enabled = cancel_enabled

    def is_cancelled(self):
        return False  # dummy monitor; always returns false

    def set_show_progress_value(self, show_progress_value):
        pass  # dummy method; does nothing

    def set_message(self, message):
        pass  # dummy method; does nothing

    def get_message(self):
        return None  # dummy method; returns none

    def set_progress(self, value):
        pass  # dummy method; does nothing

    def initialize(self, max):
        pass  # dummy method; does nothing

    def set_maximum(self, max):
        pass  # dummy method; does nothing

    def get_maximum(self):
        return None  # dummy method; returns none

    def set_indeterminate(self, indeterminate):
        pass  # dummy method; does nothing

    def is_indeterminate(self):
        return False  # dummy monitor; always returns false

    def check_canceled(self):
        if self.did_time_out:
            raise TimeoutException("Operation cancelled due to timeout of {} {}".format(self.timeout, self.time_unit))
        pass  # dummy method; does nothing

    def increment_progress(self, increment_amount):
        pass  # dummy method; does nothing

    def get_progress(self):
        return None  # dummy method; returns none

    def cancel(self):
        pass  # dummy method; does nothing

    def add_canceled_listener(self, listener):
        pass  # dummy method; does nothing

    def remove_canceled_listener(self, listener):
        pass  # dummy method; does nothing

    def set_cancel_enabled(self, enable):
        self.cancel_enabled = enable

    def is_cancel_enabled(self):
        return self.cancel_enabled

    def clear_canceled(self):
        pass  # dummy method; does nothing


class Callback:
    @staticmethod
    def dummy():
        return Dummy()


class Dummy:
    @staticmethod
    def if_null(obj):
        return obj or None


def _timeout(self):
    self.did_time_out = True
    self.callback()
    self.cancel()

# TaskMonitor Methods

@TaskMonitorAdapter.is_cancelled.getter
def is_cancelled(self):
    return False  # dummy monitor; always returns false

@TaskMonitorAdapter.set_show_progress_value.setter
def set_show_progress_value(self, show_progress_value):
    pass  # dummy method; does nothing

@TaskMonitorAdapter.set_message.setter
def set_message(self, message):
    pass  # dummy method; does nothing

@TaskMonitorAdapter.get_message.getter
def get_message(self):
    return None  # dummy method; returns none

@TaskMonitorAdapter.set_progress.setter
def set_progress(self, value):
    pass  # dummy method; does nothing

@TaskMonitorAdapter.initialize.setter
def initialize(self, max):
    pass  # dummy method; does nothing

@TaskMonitorAdapter.set_maximum.setter
def set_maximum(self, max):
    pass  # dummy method; does nothing

@TaskMonitorAdapter.get_maximum.getter
def get_maximum(self):
    return None  # dummy method; returns none

@TaskMonitorAdapter.set_indeterminate.setter
def set_indeterminate(self, indeterminate):
    pass  # dummy method; does nothing

@TaskMonitorAdapter.is_indeterminate.getter
def is_indeterminate(self):
    return False  # dummy monitor; always returns false

@TaskMonitorAdapter.check_canceled.setter
def check_canceled(self):
    if self.did_time_out:
        raise TimeoutException("Operation cancelled due to timeout of {} {}".format(self.timeout, self.time_unit))
    pass  # dummy method; does nothing

@TaskMonitorAdapter.increment_progress.setter
def increment_progress(self, increment_amount):
    pass  # dummy method; does nothing

@TaskMonitorAdapter.get_progress.getter
def get_progress(self):
    return None  # dummy method; returns none

@TaskMonitorAdapter.cancel.setter
def cancel(self):
    pass  # dummy method; does nothing

@TaskMonitorAdapter.add_canceled_listener.setter
def add_canceled_listener(self, listener):
    pass  # dummy method; does nothing

@TaskMonitorAdapter.remove_canceled_listener.setter
def remove_canceled_listener(self, listener):
    pass  # dummy method; does nothing

@TaskMonitorAdapter.set_cancel_enabled.setter
def set_cancel_enabled(self, enable):
    self.cancel_enabled = enable

@TaskMonitorAdapter.is_cancel_enabled.getter
def is_cancel_enabled(self):
    return self.cancel_enabled

@TaskMonitorAdapter.clear_canceled.setter
def clear_canceled(self):
    pass  # dummy method; does nothing