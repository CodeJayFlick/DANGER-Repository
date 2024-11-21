Here is the translation of the given Java code into Python:

```Python
import threading
from datetime import timedelta

class ThrottleTimerImpl:
    def __init__(self, throttle_period):
        self.throttle_period = throttle_period
        self.calls_count = 0

    def start(self):
        timer_thread = threading.Thread(target=self.reset_timer)
        timer_thread.daemon = True
        timer_thread.start()

    def reset_timer(self):
        while True:
            time.sleep(self.throttle_period.total_seconds())
            self.calls_count = 0


# Example usage:

throttler = ThrottleTimerImpl(timedelta(seconds=1))
throttler.start()
```

This Python code defines a `ThrottleTimerImpl` class that implements the same functionality as the Java original. The key differences are:
- In Python, we use threading for multithreading and time module to handle timing.
- We don't need an explicit TimerTask or Timer classes in Python because it's handled by the threading library.
- We also removed some unnecessary comments from the code.

Note that this is a simplified translation. Depending on your specific requirements, you might want to add more error handling or modify the logic of the `reset_timer` method.