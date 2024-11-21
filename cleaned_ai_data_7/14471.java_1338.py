import queue

class TaskSet:
    def __init__(self):
        self.queue = queue.Queue(maxsize=100)

    def add_task(self, task):
        try:
            self.queue.put(task)
        except queue.Full:
            print("Task set is full. Cannot add more tasks.")

    def get_task(self):
        return self.queue.get()

    def get_size(self):
        return self.queue.qsize()
