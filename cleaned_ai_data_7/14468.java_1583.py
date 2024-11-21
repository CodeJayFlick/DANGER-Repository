import threading
import time
import random

class App:
    def __init__(self):
        self.task_set = TaskSet()
        self.work_center = WorkCenter()

    def main(self):
        workers = self.work_center.create_workers(4, self.task_set)
        execute(workers, self.task_set)

    def execute(self, workers, task_set):
        threads = [threading.Thread(target=worker) for worker in workers]
        for thread in threads:
            thread.start()
        time.sleep(1)
        add_tasks(task_set)
        for thread in threads:
            thread.join()

    def add_tasks(self, task_set):
        random.seed(time.time())
        for _ in range(5):
            time_to_execute = abs(random.randint(0, 1000))
            task_set.add_task(Task(time_to_execute))

class TaskSet:
    def __init__(self):
        self.tasks = []

    def add_task(self, task):
        self.tasks.append(task)

class WorkCenter:
    def __init__(self):
        self.workers = []

    def create_workers(self, num_workers, task_set):
        for _ in range(num_workers):
            worker = Worker(task_set)
            self.workers.append(worker)
        return self.workers

class TaskHandler:
    pass  # No implementation needed here

class Worker(threading.Thread):
    def __init__(self, task_set):
        super().__init__()
        self.task_set = task_set

    def run(self):
        while True:
            time.sleep(1)  # Simulate some work
            if not self.task_set.tasks:
                break
            task = self.task_set.tasks.pop()
            print(f"Worker {self.name} is executing task with execution time: {task.time_to_execute}")
            time.sleep(task.time_to_execute)
            print(f"Task executed by worker {self.name}")

class Task:
    def __init__(self, time_to_execute):
        self.time_to_execute = time_to_execute

if __name__ == "__main__":
    app = App()
    app.main()
