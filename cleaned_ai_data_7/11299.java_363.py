class GScheduledTask:
    next_id = 1

    def __init__(self, group: 'GTaskGroup', task: 'GTask', priority: int):
        self.group = group
        self.task = task
        self.priority = priority
        self.id = GScheduledTask.next_id
        GScheduledTask.next_id += 1
        self.monitor = GTaskMonitor()

    def get_task(self) -> 'GTask':
        return self.task

    def get_priority(self) -> int:
        return self.priority

    def get_monitor(self) -> 'GTaskMonitor':
        return self.monitor

    def __lt__(self, other):
        if isinstance(other, GScheduledTask):
            if self.priority == other.priority:
                return self.id < other.id
            else:
                return self.priority < other.priority
        else:
            raise ValueError("Can only compare with another GScheduledTask")

    def set_thread(self, thread: 'Thread'):
        self.thread = thread

    def is_running_in_current_thread(self) -> bool:
        if hasattr(thread, "current"):
            return self.thread == getattr(thread, "current")
        else:
            return False

    def __str__(self):
        return f"{self.task.name} : {self.priority}"

    def get_group(self) -> 'GTaskGroup':
        return self.group

    def get_description(self) -> str:
        return self.task.name
