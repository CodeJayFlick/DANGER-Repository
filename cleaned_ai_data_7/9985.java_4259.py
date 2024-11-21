class TaskLauncher:
    INITIAL_DELAY_MS = 1000
    INITIAL_MODAL_DELAY_MS = 500

    def __init__(self, task):
        self._task = task
        if not task.is_modal():
            delay_ms = self.INITIAL_DELAY_MS
        else:
            delay_ms = self.INITIAL_MODAL_DELAY_MS
        self._run_task(task, None, delay_ms)

    @classmethod
    def launch(cls, task):
        TaskLauncher(task)
        return task

    @classmethod
    def launch_non_modal(cls, title, runnable):
        cls(_Task(title, True, True, False), None, 0).start()

    @classmethod
    def launch_modal(cls, title, runnable):
        cls(_Task(title, True, True, True), None, 0).start()

    @classmethod
    def start(cls, task_launcher):
        if not task_launcher._task.is_modal():
            delay_ms = TaskLauncher.INITIAL_DELAY_MS
        else:
            delay_ms = TaskLauncher.INITAL_MODAL_DELAY_MS
        task_launcher._run_task(task_launcher._task, None, delay_ms)

    def _run_task(self, task, parent, delay_ms):
        if not task.is_cancellable():
            self._show_progress_dialog(parent)
        elif not task.has_progress():
            time.sleep(delay_ms / 1000.0)  # Convert milliseconds to seconds
        else:
            TaskMonitor monitor = None
            try:
                while True:
                    if parent is None or parent.isVisible():
                        break
                    time.sleep(10)  # Wait for the window to become visible

                self._show_progress_dialog(parent)
                task.run(monitor)

            except Exception as e:
                print(f"Error: {e}")

    def _show_progress_dialog(self, parent):
        if parent is None or not parent.isVisible():
            parent = None
        TaskRunner runner = create_task_runner(self._task, parent, 0, 400)
        runner.run()

class Task:
    def __init__(self, title, cancellable, has_progress, modal):
        self.title = title
        self.cancellable = cancellable
        self.has_progress = has_progress
        self.modal = modal

    def run(self, monitor):
        pass


def create_task_runner(task, parent, delay_ms, dialog_width):
    return TaskRunner(task, parent, delay_ms, dialog_width)


class TaskRunner:
    def __init__(self, task, parent, delay_ms, dialog_width):
        self._task = task
        self._parent = parent
        self._delay_ms = delay_ms
        self._dialog_width = dialog_width

    def run(self):
        if not self._task.is_modal():
            delay_ms = TaskLauncher.INITIAL_DELAY_MS
        else:
            delay_ms = TaskLauncher.INITAL_MODAL_DELAY_MS
        time.sleep(delay_ms / 1000.0)  # Convert milliseconds to seconds
        self._show_progress_dialog()

    def _show_progress_dialog(self):
        pass


if __name__ == "__main__":
    task_launcher = TaskLauncher(_Task("My task", True, True, False))
