import threading
import time

class GTimerMonitor:
    def __init__(self):
        self.was_run = False
        self.was_cancelled = False

    def did_run(self):
        return self.was_run

    def was_cancelled(self):
        return self.was_cancelled


class GTimerTask(threading.Thread, GTimerMonitor):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback
        self.was_run = False
        self.was_cancelled = False

    def run(self):
        try:
            self.callback()
            self.was_run = True
        except Exception as e:
            print(f"Unexpected exception running timer task: {e}")

    def cancel(self):
        if not super().is_alive():
            return False
        self.was_cancelled = True
        self.stop()

    def stop(self):
        while self.is_alive():
            time.sleep(0.1)
        self.join()


class GTimer:
    _timer = None

    @staticmethod
    def get_timer():
        if not GTimer._timer:
            GTimer._timer = threading.Timer("GTimer", True)
        return GTimer._timer


    @staticmethod
    def schedule_runnable(delay, callback):
        if delay < 0:
            return GTimerMonitor()
        task = GTimerTask(callback)
        GTimer.get_timer().after_delay(task, delay)
        return task

    @staticmethod
    def schedule_repeating_runnable(delay, period, callback):
        if delay < 0:
            return GTimerMonitor()
        task = GTimerTask(callback)
        while True:
            try:
                time.sleep(period / 1000.0)  # Convert milliseconds to seconds
                task.run()
            except Exception as e:
                print(f"Unexpected exception running timer task: {e}")
            if task.was_cancelled or not task.is_alive():
                break

    @staticmethod
    def schedule_repeating_runnable_with_timer(delay, period, callback):
        if delay < 0:
            return GTimerMonitor()
        task = GTimerTask(callback)
        GTimer.get_timer().after_delay(task, delay, period / 1000.0)  # Convert milliseconds to seconds
        return task

