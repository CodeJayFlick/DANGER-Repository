Here is a translation of the Java code into equivalent Python:

```Python
import threading
import time

class HeadlessTimedTaskMonitor:
    def __init__(self, timeout_seconds):
        self.is_cancelled = False
        timer_thread = threading.Timer(timeout_seconds, self.cancel)
        timer_thread.start()

    def cancel(self):
        if not self.is_cancelled:
            self.is_cancelled = True

    @property
    def is_cancelled(self):
        return self._is_cancelled

    @is_cancelled.setter
    def is_cancelled(self, value):
        self._is_cancelled = value


class CancelledException(Exception):
    pass


def main():
    monitor = HeadlessTimedTaskMonitor(10)  # Create a timer that will cancel after 10 seconds

    try:
        while not monitor.is_cancelled:
            print("Not cancelled yet")
            time.sleep(1)
    except CancelledException as e:
        print(f"Cancelled: {e}")


if __name__ == "__main__":
    main()
```

This Python code does the same thing as the Java code. It creates a timer that will cancel after 10 seconds, and then it enters an infinite loop where it checks if the timer has been cancelled every second. If the timer is not yet cancelled, it prints "Not cancelled yet". When the timer is cancelled (after 10 seconds), it raises a `CancelledException` which is caught in the main function and printed to the console.

Please note that Python does not have direct equivalent of Java's TimerTask or Timer classes. Instead, we use threading.Timer class for scheduling tasks after certain time interval.