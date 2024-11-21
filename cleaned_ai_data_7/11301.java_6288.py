class GTaskGroup:
    next_id = 0

    def __init__(self, description: str, start_new_transaction: bool):
        self.id = GTaskGroup.next_id
        GTaskGroup.next_id += 1
        self.description = description
        self.start_new_transaction = start_new_transaction
        self.monitor = None
        self.task_list = []
        self.scheduled = False

    def add_task(self, task: 'GTask', priority: int) -> 'GScheduledTask':
        if self.scheduled:
            raise ValueError("Can't directly add new tasks on a group that has been scheduled with GTaskManager")
        return self._do_add_task(task, priority)

    def _do_add_task(self, task: 'GTask', priority: int) -> 'GScheduledTask':
        scheduled_task = GScheduledTask(self, task, priority)
        self.task_list.append(scheduled_task)
        if not hasattr(self.monitor, "set_maximum"):
            return scheduled_task
        self.monitor.set_maximum(len(self.task_list))
        return scheduled_task

    def get_tasks(self) -> list:
        return sorted(list(self.task_list))

    @property
    def task_monitor(self):
        return self.monitor

    def wants_new_transaction(self) -> bool:
        return self.start_new_transaction

    @property
    def description(self) -> str:
        return self.description

    def __eq__(self, other: 'GTaskGroup') -> int:
        if not isinstance(other, GTaskGroup):
            raise TypeError("Both objects must be of type GTaskGroup")
        return (self.id - other.id)

    def __str__(self) -> str:
        return f"Task Group: {self.description}"

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    @cancelled.setter
    def set_cancelled(self):
        self._cancelled = True

    @property
    def was_cancelled(self) -> bool:
        return self._cancelled

    def task_completed(self):
        if hasattr(self.monitor, "increment_progress"):
            self.monitor.increment_progress(1)

    def set_scheduled(self):
        self.scheduled = True


class GScheduledTask:
    pass  # This class is not implemented in the given Java code
