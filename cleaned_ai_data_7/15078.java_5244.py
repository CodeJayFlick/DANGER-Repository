import logging
import time
from threading import Thread

class Worker:
    def __init__(self, task):
        self.task = task

    def run(self):
        logging.info(f"{Thread.current().name} processing {self.task}")
        try:
            time.sleep(self.task.time_ms)
        except Exception as e:
            print("Error:", str(e))

# Example usage
class Task:
    def __init__(self, time_ms):
        self.time_ms = time_ms

task1 = Task(1000)  # task that takes 1 second to complete
worker1 = Worker(task1)
worker1.run()
