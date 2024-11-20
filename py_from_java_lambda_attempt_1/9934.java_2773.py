Here is the translation of the given Java code into equivalent Python:

```Python
class TreeTaskMonitor:
    MAX_VALUE = 0x10000000000000L
    
    def __init__(self, monitor, max):
        if isinstance(monitor, TreeTaskMonitor):
            self.monitor = monitor.monitor
            current_range_min = monitor.get_true_progress()
            current_range_max = current_range_min + monitor.chunk_size
        else:
            self.monitor = monitor
            current_range_min = 0
            current_range_max = MAX_VALUE
            self.monitor.initialize(MAX_VALUE)
        
        self.set_maximum(max)
        self.progress = 0

    def get_true_progress(self):
        return self.monitor.get_progress()

    @property
    def is_cancelled(self):
        return self.monitor.is_cancelled

    def set_show_progress_value(self, show_progress_value):
        self.monitor.set_show_progress_value(show_progress_value)

    @property
    def message(self):
        return self.monitor.message

    def set_message(self, message):
        self.monitor.set_message(message)

    def set_progress(self, value):
        self.progress = value
        self.monitor.set_progress(current_range_min + value * self.chunk_size)

    def initialize(self, max_value):
        self.set_maximum(max_value)

    @property
    def maximum(self):
        return self.max

    def set_maximum(self, max_value):
        if max_value > 0:
            self.max = max_value
            
            current_range = current_range_max - current_range_min
            self.chunk_size = max(1, current_range // self.max)
        else:
            self.max = 0
            self.chunk_size = 0

    def get_maximum(self):
        return self.max

    @property
    def indeterminate(self):
        return self.monitor.indeterminate

    def set_indeterminate(self, indeterminate):
        self.monitor.set_indeterminate(indeterminate)

    def check_cancelled(self):
        self.monitor.check_cancelled()

    def increment_progress(self, increment_amount):
        self.progress += increment_amount
        self.monitor.set_progress(current_range_min + self.progress * self.chunk_size)

    @property
    def progress_value(self):
        return self.progress

    def cancel(self):
        self.monitor.cancel()

    def add_cancelled_listener(self, listener):
        self.monitor.add_cancelled_listener(listener)

    def remove_cancelled_listener(self, listener):
        self.monitor.remove_cancelled_listener(listener)

    def set_cancel_enabled(self, enable):
        self.monitor.set_cancel_enabled(enable)

    @property
    def is_cancel_enabled(self):
        return self.monitor.is_cancel_enabled

    def clear_cancelled(self):
        self.monitor.clear_cancelled()
```

This Python code does not include the CancelledException class from Java.