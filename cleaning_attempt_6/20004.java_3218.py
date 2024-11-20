import threading

class NotifyingReference:
    def __init__(self, value=None, notify_all=True):
        self._value = value
        self.notify_all = notify_all

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, new_value):
        if self._value != new_value:
            self._value = new_value
            if self.notify_all:
                threading.NotifyAll()
            else:
                threading Notify()

    def __str__(self):
        return f"NotifyingReference(value={self.value}, notify_all={self.notify_all})"
