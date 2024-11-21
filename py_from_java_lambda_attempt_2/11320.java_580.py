Here is the translation of the Java code to Python:

```Python
class MulticastTaskListener:
    def __init__(self, a, b):
        self.a = a
        self.b = b

    def task_started(self, task):
        self.a.task_started(task)
        self.b.task_started(task)

    def task_completed(self, task, result):
        self.a.task_completed(task, result)
        self.b.task_completed(task, result)

    def task_group_scheduled(self, group):
        self.a.task_group_scheduled(group)
        self.b.task_group_scheduled(group)

    def task_scheduled(self, scheduled_task):
        self.a.task_scheduled(scheduled_task)
        self.b.task_scheduled(scheduled_task)

    def task_group_started(self, task_group):
        self.a.task_group_started(task_group)
        self.b.task_group_started(task_group)

    def remove_listener(self, listener):
        if self.a == listener:
            return self.b
        elif self.b == listener:
            return self.a
        if isinstance(self.a, MulticastTaskListener):
            self.a = (self.a).remove_listener(listener)
        if isinstance(self.b, MulticastTaskListener):
            self.b = (self.b).remove_listener(listener)
        return self

    def initialize(self):
        raise Exception("Initialize should not be called here.")

    def task_group_completed(self, task_group):
        self.a.task_group_completed(task_group)
        self.b.task_group_completed(task_group)

    def suspended_state_changed(self, suspended):
        self.a.suspended_state_changed(suspended)
        self.b.suspended_state_changed(suspended)
```

Note that Python does not have direct equivalent of Java's `@Override` annotation. However, it is a good practice to include comments or docstrings in your code to indicate which methods are overriding the parent class' methods.