Here's your Java code translated into Python:

```Python
import logging

class MaintenanceLock:
    _instance = None
    _lock = True

    def __new__(cls):
        if not isinstance(cls._instance, cls):
            cls._instance = super(MaintenanceLock, cls).__new__(cls)
        return cls._instance

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = MaintenanceLock()
        return cls._instance

    def __init__(self):
        pass

    def is_lock(self):
        return self._lock

    def set_lock(self, lock: bool):
        self._lock = lock
        logging.info("Maintenance lock is set to: %s", str(lock))
```

Please note that Python does not have a direct equivalent of Java's `synchronized` keyword. The `_instance` and the constructor (`__new__`) are used here as an approximation for maintaining thread safety in singletons, which is what your code seems to be doing.

Also, I've replaced the static logger with Python's built-in logging module.