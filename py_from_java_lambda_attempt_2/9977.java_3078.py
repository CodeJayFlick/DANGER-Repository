Here is the translation of the Java code into Python:

```Python
class BasicTaskMonitor:
    def __init__(self):
        self.listeners = set()
        self.message = None
        self.progress = 0
        self.max_progress = 0
        self.cancel_enabled = True
        self.is_cancelled = False
        self.is_indeterminate = False

    def add_listener(self, listener):
        self.listeners.add(listener)

    def remove_listener(self, listener):
        try:
            self.listeners.remove(listener)
        except KeyError:
            pass

    def increment_progress(self, amount):
        if not self.is_indeterminate and self.max_progress > 0:
            self.progress = min(self.progress + amount, self.max_progress)
        else:
            self.progress += amount

    @property
    def progress(self):
        return self.progress

    @progress.setter
    def progress(self, value):
        self.progress = value

    def is_cancelled_(self):
        return self.is_cancelled

    def check_canceled(self):
        if self.is_cancelled:
            raise CancelledException()

    def set_message(self, message):
        self.message = message

    @property
    def message(self):
        return self.message

    def cancel(self):
        was_cancelled = self.is_cancelled_
        self.is_cancelled_ = True
        if not was_cancelled:
            for listener in list(self.listeners):  # Use a copy to avoid modifying the set during iteration.
                listener.cancelled()

    def clear_canceled(self):
        self.is_cancelled_ = False

    @property
    def max_progress(self):
        return self.max_progress

    @max_progress.setter
    def max_progress(self, value):
        if not self.is_indeterminate and value > 0:
            self.progress = min(self.progress, value)
        self.max_progress = value

    @property
    def is_indeterminate_(self):
        return self.is_indeterminate_

    @is_indeterminate_.setter
    def is_indeterminate_(self, value):
        self.is_indeterminate_ = value

    def set_cancel_enabled(self, enable):
        self.cancel_enabled = enable

    @property
    def cancel_enabled_(self):
        return self.cancel_enabled_

    @cancel_enabled_.setter
    def cancel_enabled_(self, value):
        self.cancel_enabled_ = value

    def show_progress_value(self, show):
        # stub
        pass


class CancelledException(Exception):
    pass


class CancelledListener:
    def cancelled(self):
        raise NotImplementedError("cancelled method must be implemented")
```

Please note that Python does not have a direct equivalent to Java's `WeakSet` and `AtomicBoolean`. The code above uses Python's built-in set data structure for the listeners, which is garbage-collected when there are no more references. For the cancel flag, it simply uses a boolean variable without any special synchronization or visibility guarantees.