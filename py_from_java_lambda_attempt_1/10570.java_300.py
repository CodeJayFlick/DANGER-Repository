Here is the translation of the given Java code into Python:

```Python
class UnknownProgressWrappingTaskMonitor:
    def __init__(self, delegate):
        self.delegate = delegate

    def set_message(self, message):
        self.delegate.set_message(message)

    def set_progress(self, value):
        self.delegate.set_progress(value)
        self.maybe_update_maximum()

    def increment_progress(self, increment_amount):
        self.delegate.increment_progress(increment_amount)
        self.maybe_update_maximum()

    def is_cancelled(self):
        return self.delegate.is_cancelled

    def check_canceled(self):
        if self.delegate.check_canceled:
            raise CancelException("Task was cancelled")

    def maybe_update_maximum(self):
        current_max = self.delegate.get_maximum()
        progress = self.delegate.get_progress()

        seventy_five_percent = int(current_max * 0.75)
        if progress > seventy_five_percent:
            new_max = current_max + (current_max - seventy_five_percent)
            self.delegate.set_maximum(new_max)


class CancelException(Exception):
    pass
```

Note: Python does not have direct equivalent of Java's `synchronized` keyword, but you can achieve similar functionality using locks or thread-safe methods.