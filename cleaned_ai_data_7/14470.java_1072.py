import logging
from datetime import timedelta

class TaskHandler:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def handle_task(self, task: object) -> None:
        time = task.get_time()
        print(f"Sleeping for {time} milliseconds...")
        from time import sleep
        sleep(time.total_seconds())
        self.logger.info(f"It takes {time} milliseconds to finish the task")
        task.set_finished()

class Task:
    def __init__(self, time: timedelta):
        self.time = time

    def get_time(self) -> timedelta:
        return self.time

    def set_finished(self) -> None:
        pass  # implement this method in your actual code
