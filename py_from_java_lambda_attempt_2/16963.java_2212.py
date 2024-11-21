Here is the translation of the given Java code into Python:

```Python
import datetime
from functools import wraps

class MergeFuture:
    def __init__(self, callable):
        self._callable = callable
        self.created_time = datetime.datetime.now()

    @property
    def created_time(self):
        return self.created_time.strftime("%Y-%m-%d'T'%H:%M:%S.SSS'Z'")

    @property
    abstractdef get_task_name(self): pass

    @property
    abstractdef get_progress(self): pass

    def __lt__(self, other):
        if not isinstance(other, MergeFuture):
            return NotImplemented
        return self.get_task_name() < other.get_task_name()

class MainMergeFuture(MergeFuture):
    def __init__(self, task):
        super().__init__(task)
        self.binding_task = task

    @property
    def get_task_name(self):
        return self.binding_task.get_task_name()

    @property
    def get_progress(self):
        return self.binding_task.get_progress()

    def __eq__(self, other):
        if not isinstance(other, MainMergeFuture) or not super().__eq__(other):
            return NotImplemented
        return self.binding_task == other.binding_task

    def __hash__(self):
        return hash((super().__hash__(), self.binding_task))

class SubMergeFuture(MergeFuture):
    def __init__(self, task):
        super().__init__(task)
        self.binding_task = task

    @property
    def get_task_name(self):
        return self.binding_task.get_task_name()

    @property
    def get_progress(self):
        return self.binding_task.get_progress()

    def __eq__(self, other):
        if not isinstance(other, SubMergeFuture) or not super().__eq__(other):
            return NotImplemented
        return self.binding_task == other.binding_task

    def __hash__(self):
        return hash((super().__hash__(), self.binding_task))
```

Note that the `abstractdef` decorator is used to define abstract methods in Python, which are similar to Java's abstract method declarations. The `@property` decorator is used to create getter and setter properties for class attributes.