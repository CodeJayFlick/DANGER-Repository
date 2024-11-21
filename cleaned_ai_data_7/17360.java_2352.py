class StorageGroupMNodePlan:
    def __init__(self):
        self.name = None
        self.dataTTL = 0
        self.childSize = 0
        self.alignedTimeseriesIndex = 0
        super().__init__()

    def __init__(self, name: str, dataTTL: int, child_size: int):
        self.name = name
        self.dataTTL = dataTTL
        self.childSize = child_size
        super().__init__()

    @property
    def get_paths(self) -> list:
        return []

    @property
    def get_data_ttl(self) -> int:
        return self.dataTTL

    @get_data_ttl.setter
    def set_data_ttl(self, dataTTL: int):
        self.dataTTL = dataTTL

    @property
    def get_aligned_timeseries_index(self) -> int:
        return self.alignedTimeseriesIndex

    @set_aligned_timeseries_index.setter
    def set_aligned_timeseries_index(self, aligned_timeseries_index: int):
        self.alignedTimeseriesIndex = aligned_timeseries_index

    def serialize(self, buffer: bytes):
        buffer.write(int.to_bytes(1, 4, 'big'))
        buffer.write(str.encode(self.name))
        buffer.write(int.to_bytes(self.dataTTL, 8, 'big'))
        buffer.write(int.to_bytes(self.childSize, 4, 'big'))
        buffer.write(int.to_bytes(self.alignedTimeseriesIndex, 4, 'big'))

    def deserialize(self, buffer: bytes):
        self.name = str(buffer.read().decode('utf-8'))
        self.dataTTL = int.from_bytes(buffer.read(8), 'big')
        self.childSize = int.from_bytes(buffer.read(4), 'big')
        if buffer.tell() < len(buffer):
            self.alignedTimeseriesIndex = int.from_bytes(buffer.read(4), 'big')
        else:
            self.alignedTimeseriesIndex = 0

    def __str__(self) -> str:
        return f"StorageGroupMNodePlan({self.name}, {self.dataTTL}, {self.childSize}, {self.alignedTimeseriesIndex})"

    def __eq__(self, other):
        if not isinstance(other, StorageGroupMNodePlan):
            return False
        return self.name == other.name and self.dataTTL == other.dataTTL and self.childSize == other.childSize and self.alignedTimeseriesIndex == other.alignedTimeseriesIndex

    def __hash__(self) -> int:
        return hash((self.name, self.dataTTL, self.childSize, self.alignedTimeseriesIndex))
