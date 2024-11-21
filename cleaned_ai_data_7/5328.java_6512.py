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
