Here is the translation of the given Java code into Python:

```Python
class DeleteDataOperator:
    def __init__(self):
        self.paths = []
        self.startTime = None
        self.endTime = None

    @property
    def paths(self):
        return self._paths

    @paths.setter
    def paths(self, value):
        self._paths = value

    def add_path(self, path):
        self(paths).append(path)

    @property
    def start_time(self):
        return self._start_time

    @start_time.setter
    def start_time(self, time):
        self._start_time = time

    @property
    def end_time(self):
        return self._end_time

    @end_time.setter
    def end_time(self, time):
        self._end_time = time

    def generate_physical_plan(self, generator):
        from . import DeletePlan  # Assuming the DeletePlan class is in a separate file.
        return DeletePlan(self.start_time, self.end_time, self.paths)
```

Please note that Python does not have direct equivalent of Java's `List` and other data structures. The above code uses Python's built-in list (`self._paths`) to store paths.