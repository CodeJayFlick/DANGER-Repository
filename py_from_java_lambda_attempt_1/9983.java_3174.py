Here is the translation of the Java code into Python:

```Python
class TaskBuilder:
    def __init__(self):
        self.title = None
        self.runnable = None
        self.parent = None
        self.launch_delay = -1
        self.dialog_width = 0
        self.has_progress = True
        self.can_cancel = True
        self.wait_for_task_completion = False
        self.status_text_alignment = 'center'

    def with_runnable(self, runnable):
        return TaskBuilder(runnable)

    def with_task(self, task):
        return TaskBuilder(task.get_title(), task)

    @staticmethod
    def from_runnable(runnable):
        builder = TaskBuilder()
        builder.runnable = Objects.requireNonNull(runnable)
        return builder

    @staticmethod
    def from_task(title, task):
        builder = TaskBuilder.from_runnable(None)
        builder.title = title
        builder.runnable = task
        return builder

    def set_title(self, title):
        self.title = title
        return self

    def set_has_progress(self, has_progress):
        self.has_progress = has_progress
        return self

    def set_can_cancel(self, can_cancel):
        self.can_cancel = can_cancel
        return self

    def set_parent(self, parent):
        self.parent = parent
        return self

    def set_launch_delay(self, delay):
        if delay < 0:
            raise ValueError("Launch delay must be greater than or equal to zero")
        self.launch_delay = delay
        return self

    def set_dialog_width(self, width):
        if width <= 0:
            raise ValueError("Dialog width must be greater than zero")
        self.dialog_width = width
        return self

    def set_status_text_alignment(self, alignment):
        if alignment not in ['leading', 'center', 'trailing']:
            raise ValueError("Invalid alignment argument: " + str(alignment))
        self.status_text_alignment = alignment
        return self

    def launch_modal(self):
        if not self.title:
            raise ValueError("Task title cannot be null")
        is_modal = True
        task = TaskBuilderTask(is_modal)
        if SystemUtilities.is_in_headless_mode():
            task.monitored_run(TaskMonitor.DUMMY)
            return
        delay = get_delay(self.launch_delay, is_modal)
        new TaskLauncher(task, self.parent, delay, self.dialog_width)

    def launch_nonmodal(self):
        if not self.title:
            raise ValueError("Task title cannot be null")
        is_modal = False
        task = TaskBuilderTask(is_modal)
        if SystemUtilities.is_in_headless_mode():
            task.monitored_run(TaskMonitor.DUMMY)
            return
        delay = get_delay(self.launch_delay, is_modal)
        new TaskLauncher(task, self.parent, delay, self.dialog_width)

    def launch_background(self, monitor):
        Objects.requireNonNull(monitor)
        BackgroundThreadTaskLauncher launcher = 
            BackgroundThreadTaskLauncher(new TaskBuilderTask(False))
        launcher.run(monitor)


class Task:
    def __init__(self, title, can_cancel, has_progress, is_modal, wait_for_task_completion):
        self.title = title
        self.can_cancel = can_cancel
        self.has_progress = has_progress
        self.is_modal = is_modal
        self.wait_for_task_completion = wait_for_task_completion

    def get_title(self):
        return self.title


class TaskBuilderTask(Task):
    def __init__(self, is_modal):
        super().__init__('', False, True, is_modal, False)

    def monitored_run(self, monitor):
        self.runnable.monitored_run(monitor)


def get_delay(user_delay, is_modal):
    if user_delay >= 0:
        return user_delay
    if is_modal:
        return TaskLauncher.INITIAL_MODAL_DELAY_MS
    return TaskLauncher.INITIAL_DELAY_MS


class SystemUtilities:
    @staticmethod
    def requireNonNull(obj):
        if obj is None:
            raise NullPointerException("Object cannot be null")
        return obj

    @staticmethod
    def is_in_headless_mode():
        # This method should check whether the system is in headless mode.
        pass


class TaskMonitor:
    DUMMY = 'dummy'


def main():
    task_builder = TaskBuilder.from_runnable(None)
    task_builder.set_title('Task Title')
    task_builder.set_has_progress(True)
    task_builder.set_can_cancel(False)
    task_builder.launch_modal()


if __name__ == "__main__":
    main()
```

Note that this is a direct translation of the Java code into Python, and it may not be perfect. The original Java code has some complex logic and many classes, which can make it difficult to translate directly into Python.