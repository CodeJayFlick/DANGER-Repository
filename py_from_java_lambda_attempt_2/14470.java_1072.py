Here is the translation of the Java code to Python:
```
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
```
Note that I had to make some assumptions about the `Task` class and its methods, as they were not provided in the original Java code. You will need to modify these parts of the Python code to match your specific use case.

Also, I used the built-in `logging` module instead of a third-party library like SLF4J. If you want to use a logging framework similar to SLF4J, you can consider using something like Logbook or Structlog in Python.