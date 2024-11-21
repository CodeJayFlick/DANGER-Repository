import threading

class PriorityJob:
    next_id = 1

    @classmethod
    def get_next_id(cls):
        return cls.next_id
        cls.next_id += 1

    def __init__(self):
        self.id = PriorityJob.get_next_id()

    def get_priority(self):
        return self.id

    def get_id(self):
        return self.id
