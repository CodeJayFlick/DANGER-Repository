import threading
import time

class TaskScheduler:
    def __init__(self, comp):
        self.comp = comp
        self.scheduled_task = None
        self.scheduled_delay = 0
        self.current_task = None
        self.current_delay = 0
        self.task_thread = None

    def set(self, task, delay):
        if not self.task_thread:
            self.task_thread = threading.Thread(target=self.run)
            self.task_thread.setDaemon(True)  # Set as daemon thread
            self.task_thread.start()
        self.scheduled_task = task
        self.scheduled_delay = delay

    def run(self):
        while True:
            if self.has_task():
                tm = self.comp.show_progress(self.current_task, self.current_delay)
                self.current_task.run(tm)

    def get_current_thread(self):
        return self.task_thread

    def wait_for_current_task(self):
        t = self.get_current_thread()
        if t is not None:
            try:
                t.join()
            except threading.InterruptException:
                pass  # We don't care about interrupts here
        else:
            time.sleep(0.1)  # Wait for a short while to avoid busy waiting

    def clear_scheduled_task(self):
        self.scheduled_task = None

    def is_busy(self):
        return self.task_thread is not None or self.scheduled_task is not None

    def has_task(self):
        if self.scheduled_task is None:
            self.task_thread = None
            self.current_task = None
            return False
        self.current_task = self.scheduled_task
        self.current_delay = self.scheduled_delay
        self.scheduled_task = None
        return True

# Example usage:
comp = ...  # Your DialogComponentProvider instance
scheduler = TaskScheduler(comp)
scheduler.set(task, delay)  # Set the next task to run
