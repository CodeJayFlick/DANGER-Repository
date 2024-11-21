Here is the translation of the Java code to Python:
```
class TaskListener:
    def __init__(self):
        pass

    def task_completed(self, task: 'Task') -> None:
        """Notification that the task completed."""
        pass  # implement me!

    def task_cancelled(self, task: 'Task') -> None:
        """Notification that the task was canceled."""
        pass  # implement me!
```
Note that I've kept the method signatures and docstrings similar to the original Java code. However, in Python, we don't need explicit `public` or `private` access modifiers, nor do we need a separate interface definition for abstract methods.

Also, since Python is dynamically typed, I didn't include type hints like `TaskListener` does not have any type parameters and Task is the class that was running.