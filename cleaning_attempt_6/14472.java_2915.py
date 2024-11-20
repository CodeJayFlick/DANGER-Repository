# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import copy

class WorkCenter:
    def __init__(self):
        self.leader = None
        self.workers = []

    def create_workers(self, num_workers, task_set, task_handler):
        for i in range(1, num_workers + 1):
            worker = Worker(i, self, task_set, task_handler)
            self.workers.append(worker)
        self.promote_leader()

    def add_worker(self, worker):
        self.workers.append(worker)

    def remove_worker(self, worker):
        if worker in self.workers:
            self.workers.remove(worker)

    @property
    def leader(self):
        return self._leader

    @leader.setter
    def leader(self, value):
        self._leader = value

    def promote_leader(self):
        if len(self.workers) > 0:
            self.leader = self.workers[0]

    @property
    def workers(self):
        return copy.deepcopy(self._workers)

class Worker:
    def __init__(self, id, work_center, task_set, task_handler):
        self.id = id
        self.work_center = work_center
        self.task_set = task_set
        self.task_handler = task_handler

# Example usage:
work_center = WorkCenter()
work_center.create_workers(5, TaskSet(), TaskHandler())
print(work_center.leader)
