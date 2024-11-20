class Task:
    _id_generator = [0]

    def __init__(self, time_ms):
        self.id = Task._id_generator[0] += 1
        self.time_ms = time_ms

    @property
    def id(self):
        return self.id

    @property
    def time_ms(self):
        return self.time_ms

    def __str__(self):
        return f"id={self.id} timeMs={self.time_ms}"
