class CompoundTask:
    def __init__(self, tasks: list, title: str):
        self.tasks = tasks
        super().__init__(title)

    @property
    def can_cancel(self) -> bool:
        return self.tasks[0].can_cancel

    @property
    def has_progress(self) -> bool:
        return self.tasks[0].has_progress

    @property
    def is_modal(self) -> bool:
        return self.tasks[0].is_modal


class TaskMonitorSplitter:
    @staticmethod
    def split_task_monitor(monitor: object, num_tasks: int):
        # Assuming the monitor splitting logic here...
        pass


def run_compound_task(compound_task: CompoundTask, task_monitor: object) -> None:
    sub_monitors = [task_monitor for _ in range(len(compound_task.tasks))]
    try:
        for i, task in enumerate(compound_task.tasks):
            task.run(sub_monitors[i])
    except CancelledException as e:
        raise e


class TaskMonitor:
    pass

class CancelledException(Exception):
    pass
