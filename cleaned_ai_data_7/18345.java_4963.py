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
