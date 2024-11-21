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
