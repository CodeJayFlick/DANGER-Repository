import threading
from queue import Queue
from time import sleep
from datetime import timedelta

class TaskLauncherSpy:
    def __init__(self, task):
        self.task = task

    def run(self):
        # simulate running a task
        pass


class FastModalTask:
    def __init__(self):
        super().__init__()
        self.name = "Fast Modal Task"

    def run(self):
        print(f"{self.name} started...")
        sleep(10)
        print(f"{self.name} finished.")


class SlowModalTask:
    def __init__(self):
        super().__init__()
        self.name = "Slow Modal Task"

    def run(self):
        print(f"{self.name} started...")
        sleep(20)
        print(f"{self.name} finished.")


class TDEvent:
    def __init__(self, message):
        self.message = message

    @property
    def thread_name(self):
        return threading.current_thread().name


def launch_task(task):
    task_launcher = TaskLauncherSpy(task)
    task_launcher.run()


# usage example
task1 = FastModalTask()
launch_task(task1)

task2 = SlowModalTask()
launch_task(task2)
