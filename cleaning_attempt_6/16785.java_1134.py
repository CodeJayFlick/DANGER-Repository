class Event:
    def __init__(self,
                 device: str,
                 timestamp: int,
                 measurements: list[str],
                 types: list[TSDataType],
                 values: list[object]):
        self.device = device
        self.timestamp = timestamp
        self.measurements = measurements
        self.types = types
        self.values = values

    @property
    def get_types(self) -> list[TSDataType]:
        return self.types

    @get_types.setter
    def set_types(self, value: list[TSDataType]):
        self.types = value

    @property
    def device(self) -> str:
        return self.device

    @device.setter
    def device(self, value: str):
        self.device = value

    @property
    def timestamp(self) -> int:
        return self.timestamp

    @timestamp.setter
    def timestamp(self, value: int):
        self.timestamp = value

    @property
    def measurements(self) -> list[str]:
        return self.measurements

    @measurements.setter
    def measurements(self, value: list[str]):
        self.measurements = value

    @property
    def values(self) -> list[object]:
        return self.values

    @values.setter
    def values(self, value: list[object]):
        self.values = value
