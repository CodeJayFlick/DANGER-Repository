Here is the translation of the Java code into Python:

```Python
import threading
from tkinter import *
from tkinter.messagebox import showinfo

class TaskDialog:
    def __init__(self, center_on_comp=None, title="", modal=True, can_cancel=False):
        self.center_on_component = center_on_comp
        self.title = title
        self.modal = modal
        self.can_cancel = can_cancel
        self.supports_progress = False
        self.shown = threading.Event()

    def setup(self, can_cancel):
        if not hasattr(self, 'main_panel'):
            self.main_panel = Frame()
            self.add_work_panel(self.main_panel)
        if self.supports_progress:
            self.install_progress_monitor()
        else:
            self.install_activity_display()
        if can_cancel:
            self.add_cancel_button()

    def prompt_to_verify_cancel(self):
        return askyesno("Cancel", "Do you really want to cancel the task?")

    def is_installed(self, c):
        components = list(self.main_panel.winfo_children())
        for component in components:
            if c == component:
                return True
        return False

    def install_progress_monitor(self):
        self.main_panel.delete(0, END)
        self.main_panel.insert(END, "Progress Monitor")
        self.repack()

    def install_activity_display(self):
        self.main_panel.delete(0, END)
        self.main_panel.insert(END, "Activity Display")
        self.repack()

    def cancel_callback(self):
        threading.runLater(lambda: verify_cancel())

    def set_cancel_enabled(self, enable):
        if hasattr(self, 'monitor_component'):
            self.monitor_component.set_cancel_enabled(enable)

    def is_cancel_enabled(self):
        return self.monitor_component.is_cancel_enabled() if hasattr(self, 'monitor_component') else False

    def task_processed(self):
        threading.runLater(lambda: close_dialog())

    def show(self, delay=0):
        if not self.modal:
            do_show_non_modal(delay)
        elif delay > 0:
            give_the_task_thread_a_chance_to_complete(delay)

    def was_shown(self):
        return self.shown.is_set()

    def cleanup(self):
        threading.runLater(lambda: cancel_timer().cancel())
        message_updater.dispose()

    # TaskMonitor Methods
    def set_message(self, str):
        if hasattr(self, 'new_message'):
            self.new_message.set(str)
            message_updater.update()

    def get_message(self):
        return self.get_status_text() if hasattr(self, 'monitor_component') else ""

    def show_progress_value(self, show_progress_value):
        if hasattr(self, 'monitor_component'):
            self.monitor_component.show_progress_value(show_progress_value)

    def set_progress(self, progress):
        if hasattr(self, 'monitor_component'):
            self.monitor_component.set_progress(progress)

    def initialize(self, max):
        if not hasattr(self, 'max') or max <= 0:
            return
        if hasattr(self, 'monitor_component'):
            self.monitor_component.initialize(max)
        else:
            supports_progress = True

    # End TaskMonitor Methods


def main():
    root = Tk()
    task_dialog = TaskDialog(center_on_comp=root, title="Task Dialog", modal=True, can_cancel=False)

if __name__ == "__main__":
    main()

```

Note: This is a direct translation of the Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific use case.