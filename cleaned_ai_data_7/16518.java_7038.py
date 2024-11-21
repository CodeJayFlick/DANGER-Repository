class PreviousFillArguments:
    def __init__(self,
                 path: 'org.apache.iotdb.db.metadata.PartialPath',
                 data_type: str,
                 query_time: int,
                 before_range: int,
                 device_measurements: set):
        self.path = path
        self.data_type = data_type
        self.query_time = query_time
        self.before_range = before_range
        self.device_measurements = device_measurements

    @property
    def path(self) -> 'org.apache.iotdb.db.metadata.PartialPath':
        return self._path

    @property
    def data_type(self) -> str:
        return self._data_type

    @property
    def query_time(self) -> int:
        return self._query_time

    @property
    def before_range(self) -> int:
        return self._before_range

    @property
    def device_measurements(self) -> set:
        return self._device_measurements
