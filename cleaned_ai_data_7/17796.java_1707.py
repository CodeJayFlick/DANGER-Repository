class Counter:
    BASE = 1377
    def __init__(self):
        self.counter = Counter.BASE
        self.is_stopped = True

    def on_create(self, attributes):
        self.counter = Counter.BASE
        self.is_stopped = False

    def start(self):
        self.is_stopped = False

    def stop(self):
        self.is_stopped = True

    def fire(self, timestamp, value):
        if isinstance(value, int): return type(value)(self.counter + 1)
        elif isinstance(value, float): return type(value)(float(self.counter + 1))
        else: raise ValueError("Unsupported data type")

    @property
    def counter(self):
        return self._counter

    @counter.setter
    def counter(self, value):
        self._counter = value

    @property
    def is_stopped(self):
        return self._is_stopped

    @is_stopped.setter
    def is_stopped(self, value):
        self._is_stopped = value


# Example usage:
c = Counter()
print(c.counter)  # prints: 1377
c.on_create(None)
print(c.is_stopped)  # prints: False
c.start()
print(c.is_stopped)  # prints: True
