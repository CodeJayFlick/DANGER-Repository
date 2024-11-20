import unittest
from threading import Thread, Lock
from time import sleep

class GTaskManager:
    def __init__(self):
        self.tasks = []
        self.groups = []

    def schedule_task(self, task, delay=0, group=None):
        if group is not None and group in self.groups:
            self.groups[group].add_task(task)
        else:
            self.tasks.append((task, delay))

    def run_next_task(self):
        while True:
            for i, (task, _) in enumerate(self.tasks):
                task.run()
                del self.tasks[i]
            if not self.tasks and not self.groups:
                break
            sleep(0.1)

class GTaskResult:
    def __init__(self, description):
        self.description = description

class SimpleTask:
    def __init__(self, name):
        self.name = name
        self.did_run = False

    def run(self):
        pass

class LatchedTask(SimpleTask):
    def __init__(self, name):
        super().__init__(name)
        self.latch = Lock()

    def run(self):
        try:
            if not self.latch.acquire(2):  # timeout
                assert False, "Latch await expired!"
        except KeyboardInterrupt as e:
            raise CancelledException from e

class YieldingTask(SimpleTask):
    def __init__(self, name):
        super().__init__(name)

    def run(self):
        pass

class GTaskGroup:
    def __init__(self, group_name, is_group=True):
        self.group_name = group_name
        self.tasks = []
        self.is_group = is_group

    def add_task(self, task, delay=0):
        self.tasks.append((task, delay))

class TaskMonitor:
    def cancel(self):
        pass

class GTaskManagerFactory:
    @staticmethod
    def get_task_manager(obj):
        return GTaskManager()

class CancelledException(Exception):
    pass


class TestGTaskManager(unittest.TestCase):

    def setUp(self):
        self.domain_object = GenericDomainObjectDB()
        self.gtask_manager = GTaskManager()
        self.task_results = []

    def test_run_one_task(self):
        task = SimpleTask("Task 1")
        self.gtask_manager.schedule_task(task, 5)
        while True:
            if not self.gtask_manager.is_running():
                break
            sleep(0.1)

        assert task.did_run

    # ... other tests ...

if __name__ == '__main__':
    unittest.main()
