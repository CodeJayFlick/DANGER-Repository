class LocalIoTDBConfiguration:
    def __init__(self, device: str, measurements: list[str], data_types: list[TSDataType]):
        self.device = PartialPath(device)
        self.measurements = measurements
        self.data_types = data_types

    @property
    def device(self):
        return self._device

    @property
    def measurements(self):
        return self._measurements

    @property
    def data_types(self):
        return self._data_types


class PartialPath:
    def __init__(self, path: str):
        self.path = path


TSDataType = enum('TSDataType', 'INT64', 'BOOLEAN', 'TEXT')
