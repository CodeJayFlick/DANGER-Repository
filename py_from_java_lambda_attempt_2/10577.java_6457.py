Here is the translation of the Java code to Python:

```Python
import time
import threading

class Watchdog:
    def __init__(self, default_timeout_ms, timeout_method):
        self.default_watchdog_timeout_ms = default_timeout_ms
        self.timeout_method = timeout_method
        self.watchdog_timer = None
        self.enabled = False
        self.expires_at = 0

    def close(self):
        if self.watchdog_timer is not None:
            self.watchdog_timer.cancel()
        self.watchdog_timer = None
        self.timeout_method = None

    def watchdog_worker(self):
        while True:
            now = time.time() * 1000
            if self.expires_at > 0 and now >= self.expires_at:
                self.enabled = False
                self.timeout_method()
            elif not self.enabled:
                break
            else:
                threading.Timer((self.default_watchdog_timeout_ms - (now % self.default_watchdog_timeout_ms)) / 1000.0, self.watchdog_worker).start()

    def set_enabled(self, b):
        if b:
            self.expires_at = time.time() * 1000 + self.default_watchdog_timeout_ms
        else:
            self.expires_at = -1

    @property
    def is_enabled(self):
        return self.expires_at > 0

    def arm(self):
        self.set_enabled(True)

    def disarm(self):
        self.set_enabled(False)
```

Note that Python does not have a direct equivalent to Java's `AtomicLong` or `GTimer`, so I had to implement the watchdog timer using Python's built-in `threading.Timer`. Also, Python does not support finalizers like Java's `finalize()` method.