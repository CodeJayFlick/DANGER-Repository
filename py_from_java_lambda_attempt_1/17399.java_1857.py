Here is the translation of the Java code to Python:

```Python
import logging
from concurrent.futures import ThreadPoolExecutor, scheduled
from datetime import timedelta, datetime

class SessionTimeoutManager:
    _logger = logging.getLogger(__name__)
    MINIMUM_CLEANUP_PERIOD = 2000
    SESSION_TIMEOUT = None

    def __init__(self):
        if self.SESSION_TIMEOUT == 0:
            return
        
        self.session_id_to_last_active_time = {}
        self.executor_service = ThreadPoolExecutor(max_workers=1, name="session-timeout-manager")

        self.executor_service.schedule_at_fixed_rate(
            lambda: self._cleanup(),
            0,
            max(self.MINIMUM_CLEANUP_PERIOD, int(self.SESSION_TIMEOUT / 5)),
            timedelta(milliseconds=1)
        )

    def register(self, id):
        if self.SESSION_TIMEOUT == 0:
            return
        
        self.session_id_to_last_active_time[id] = datetime.now()

    def unregister(self, id):
        if self.SESSION_TIMEOUT == 0:
            # Assuming SessionManager is a class with an instance method releaseSessionResource
            return SessionManager().release_session_resource(id)
        
        if SessionManager().release_session_resource(id):
            return id in self.session_id_to_last_active_time and del self.session_id_to_last_active_time[id]
        else:
            return False

    def refresh(self, id):
        if self.SESSION_TIMEOUT == 0:
            return
        
        self.session_id_to_last_active_time = {k: datetime.now() for k in list(self.session_id_to_last_active_time.keys())}

    def _cleanup(self):
        current_time = datetime.now()
        for entry in list(self.session_id_to_last_active_time.items()):
            if (entry[1] + timedelta(milliseconds=self.SESSION_TIMEOUT)).timestamp() < current_time.timestamp():
                self.unregister(entry[0])
                self._logger.debug(f"session-{entry[0]} timed out in {current_time - entry[1]}")

    @classmethod
    def get_instance(cls):
        return cls._instance

SessionTimeoutManager._instance = SessionTimeoutManager()
```

Please note that Python does not have a direct equivalent to Java's `ScheduledExecutorService`. The above code uses the built-in `threading` module and its `Timer` class, which is different from what you would typically use in Java.