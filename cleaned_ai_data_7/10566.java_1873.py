class TaskListener:
    def __init__(self):
        pass

    def task_completed(self, task: 'Task') -> None:
        """Notification that the task completed."""
        pass  # implement me!

    def task_cancelled(self, task: 'Task') -> None:
        """Notification that the task was canceled."""
        pass  # implement me!
