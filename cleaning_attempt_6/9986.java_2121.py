import threading
from tkinter import *
from tkinter.messagebox import showinfo
from tkinter.filedialog import asksaveasfile

class TaskMonitorComponent:
    def __init__(self):
        self.listeners = []
        self.progress_bar = None
        self.cancel_button = None
        self.main_content_panel = None
        self.progress_panel = None
        self.message_label = None
        self.is_cancelled = False
        self.last_progress = -1
        self.progress = 0
        self.last_max_progress = -1
        self.max_progress = 0
        self.scale_factor = 1

    def add_cancelled_listener(self, listener):
        self.listeners.append(listener)

    def remove_cancelled_listener(self, listener):
        if listener in self.listeners:
            self.listeners.remove(listener)

    def increment_progress(self, amount):
        self.progress += amount

    def get_progress(self):
        return self.progress

    def is_cancelled(self):
        return self.is_cancelled

    def check_canceled(self):
        if self.is_cancelled:
            raise CancelledException()

    def set_message(self, message):
        self.message_label.config(text=message)

    def get_message(self):
        return self.message_label.cget("text")

    def set_progress(self, value):
        if self.progress == value:
            return
        self.progress = value

    def initialize(self, max_value):
        self.max_progress = max_value
        self.set_progress(0)

    def set_maximum(self, max):
        self.max_progress = max
        if self.progress > self.max_progress:
            self.progress = self.max_progress
        self.update()

    def is_indeterminate(self):
        return False

    def set_cancel_enabled(self, enable):
        pass

    def cancel(self):
        self.is_cancelled = True
        for listener in self.listeners:
            listener.cancelled()
        showinfo("Task Canceled", "The task has been canceled.")

    def clear_canceled(self):
        self.is_cancelled = False

    def set_show_progress_value(self, value):
        pass

    def get_maximum(self):
        return self.max_progress

    def reset(self):
        self.is_cancelled = False
        for listener in self.listeners:
            listener.reset()

class CancelledException(Exception):
    pass

root = Tk()
task_monitor_component = TaskMonitorComponent()
# Add your code here to use the task monitor component.
