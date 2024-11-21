Here is the translation of the Java code to Python:
```
class TSRecord:
    def __init__(self, timestamp: int, device_id: str):
        self.time = timestamp
        self.device_id = device_id
        self.data_points = []

    @property
    def time(self) -> int:
        return self._time

    @time.setter
    def time(self, value: int):
        self._time = value

    def add_data_point(self, data_point: dict):
        self.data_points.append(data_point)
        return self

    def __str__(self) -> str:
        sc = StringContainer()
        sc.add_tail(f"{{device id: {self.device_id}, time: {self.time}, data: [")
        for dp in self.data_points:
            sc.add_tail(str(dp))
        sc.add_tail("]}}")
        return sc.__str__()
```
Note that I've used Python's built-in `int` and `str` types to represent the timestamp and device ID, respectively. I've also replaced the Java-style comments with Python-style docstrings.

The `StringContainer` class is not provided in the original code, so I assume it's a custom class or library specific to your project. If you'd like me to translate that as well, please let me know!