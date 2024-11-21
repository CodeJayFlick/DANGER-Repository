import threading

class SynchronizedReference:
    def __init__(self, value=None):
        self._value = value

    @property
    def value(self):
        with self.lock:
            return self._value

    @value.setter
    def value(self, new_value):
        with self.lock:
            self._value = new_value

    def __init_lock(self):
        if not hasattr(self, 'lock'):
            self.lock = threading.Lock()

    lock = property(__init_lock)

class Nullable:
    pass  # equivalent to Java's @Nullable annotation
