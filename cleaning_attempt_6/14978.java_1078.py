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
