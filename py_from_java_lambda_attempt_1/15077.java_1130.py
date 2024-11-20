Here is the translation of the given Java code into Python:

```Python
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
```

Please note that Python does not have a direct equivalent to Java's `AtomicInteger`. In this translation, I used a list with one element as an approximation of the atomic integer. This is because in Python, all variables are passed by object reference and operations on them are thread-safe (as long as you don't share the same variable across multiple threads).