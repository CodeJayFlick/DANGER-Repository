Here is a translation of the provided Java code into equivalent Python:

```Python
import threading
from queue import Queue
from tkinter import Tk, Toplevel, Label, Button, StringVar, IntVar
from tkinter.messagebox import showinfo

class TaskRunner:
    def __init__(self, task, parent, delay_ms, dialog_width):
        self.task = task
        self.parent = parent
        self.delay_ms = delay_ms
        self.dialog_width = dialog_width
        self.finished = threading.Event()
        self.task_dialog = None

    def run(self):
        internal_monitor = BasicTaskMonitor()
        monitor = WrappingTaskMonitor(internal_monitor)
        start_task_thread(monitor)
        show_task_dialog(monitor)
        wait_for_modal_task()

    def wait_for_modal_task(self):
        if not self.task.is_modal():
            return
        try:
            self.finished.wait()
        except threading.ThreadError as e:
            print(f"Task Launcher unexpectedly interrupted waiting for task thread: {e}")

    def build_task_dialog(self):
        center_over_component = self.parent
        current_parent = center_over_component
        if current_parent is not None:
            current_parent = WindowUtilities.window_for_component(center_over_component)
        else:
            center_over_component = None

        dialog = TaskDialog(center_over_component, self.task, self.finished)
        dialog.set_minimum_size(self.dialog_width, 0)
        dialog.set_status_justification(self.task.get_status_text_alignment())
        return dialog

    def start_task_thread(self, monitor):
        task_utilities.add_tracked_task(self.task, monitor)

        name = f"Task - {self.task.get_task_title()}"
        pool = GThreadPool.get_shared_thread_pool(Swing.GSWING_THREAD_POOL_NAME)
        executor = pool.get_executor()
        executor.submit(lambda: self.run_task(monitor))

    def run_task(self, monitor):
        try:
            self.task.monitored_run(monitor)
        finally:
            task_finished()

    def show_task_dialog(self, monitor):
        if Swing.is_swing_thread():
            self.build_and_show_task_dialog(monitor)
        else:
            Swing.run_later(lambda: self.build_and_show_task_dialog(monitor))

    def build_and_show_task_dialog(self, monitor):
        dialog = self.build_task_dialog()
        monitor.set_delegate(dialog)  # initialize the dialog to the current monitor state
        dialog.show(max(self.delay_ms, 0))

    @property
    def is_finished(self):
        return not self.finished.is_set()

def task_finished():
    global finished
    finished.set()

class BasicTaskMonitor:
    pass

class WrappingTaskMonitor:
    def __init__(self, internal_monitor):
        self.internal_monitor = internal_monitor
        self.delegate = None

    @property
    def is_cancel_enabled(self):
        return self.internal_monitor.is_cancel_enabled

    @is_cancel_enabled.setter
    def is_cancel_enabled(self, value):
        self.internal_monitor.set_cancel_enabled(value)

    def set_delegate(self, dialog):
        self.delegate = dialog

class TaskDialog:
    pass

class WindowUtilities:
    @staticmethod
    def window_for_component(component):
        return None  # implement this method to get the window for a given component

def Swing():
    class GThreadPool:
        @staticmethod
        def get_shared_thread_pool(name):
            return None  # implement this method to get the shared thread pool with the given name

        @staticmethod
        def get_executor(pool=None):
            if pool is not None and isinstance(pool, threading.ThreadPool):
                return pool.getExecutor()
            else:
                return None  # implement this method to get an executor from a given thread pool or create one

    class TaskUtilities:
        @staticmethod
        def add_tracked_task(task, monitor):
            pass  # implement this method to track the task with the given monitor

class GThreadPool(threading.ThreadPool):
    pass

def main():
    parent = Tk()
    delay_ms = 1000
    dialog_width = 400
    task = TaskRunner(None)  # create a task instance and use it in the TaskRunner constructor
    runner = TaskRunner(task, parent, delay_ms, dialog_width)
    runner.run()

if __name__ == "__main__":
    main()
```

Please note that this translation is not perfect as Python does not have direct equivalents for some Java classes or methods. Some parts of the code may need to be adjusted based on your specific requirements and constraints.

Also, please ensure you implement all missing functions (like `WindowUtilities.window_for_component`, `GThreadPool.get_shared_thread_pool` and `TaskUtilities.add_tracked_task`) according to your needs.