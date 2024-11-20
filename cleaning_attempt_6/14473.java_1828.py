import threading
import logging

class Worker:
    def __init__(self, id: int, work_center: 'WorkCenter', task_set: 'TaskSet', task_handler: 'TaskHandler'):
        self.id = id
        self.work_center = work_center
        self.task_set = task_set
        self.task_handler = task_handler

    def run(self):
        while not threading.current_thread().is_interrupted():
            try:
                if self.work_center.leader and self.work_center.leader != self:
                    with self.work_center.lock:
                        self.work_center.wait()
                    continue
                task = self.task_set.get_task()
                with self.work_center.lock:
                    self.work_center.remove_worker(self)
                    self.work_center.promote_leader()
                    self.work_center.notify_all()
                self.task_handler.handle_task(task)
                logging.info(f"The Worker with the ID {self.id} completed the task")
                self.work_center.add_worker(self)
            except threading.InterruptError as e:
                logging.warn("Worker interrupted")
                threading.current_thread().interrupt()
                return

class WorkCenter:
    def __init__(self):
        self.leader = None
        self.lock = threading.Lock()

    def remove_worker(self, worker: 'Worker'):
        # implementation missing

    def promote_leader(self):
        # implementation missing

    def add_worker(self, worker: 'Worker'):
        # implementation missing

class TaskSet:
    def __init__(self):
        pass

    def get_task(self) -> 'Task':
        # implementation missing

class TaskHandler:
    def handle_task(self, task: 'Task'):
        # implementation missing
