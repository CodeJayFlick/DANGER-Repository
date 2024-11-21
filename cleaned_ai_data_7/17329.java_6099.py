class DropIndexPlan:
    def __init__(self):
        self.paths = []
        self.index_type = None

    @property
    def paths(self):
        return self._paths

    @paths.setter
    def paths(self, value):
        self._paths = value

    @property
    def index_type(self):
        return self._index_type

    @index_type.setter
    def index_type(self, value):
        self._index_type = value

    def serialize(self, stream):
        PhysicalPlanType.serialize(stream)
        stream.write(int(self.index_type).to_bytes(1, 'big'))
        stream.write(len(self.paths).to_bytes(4, 'big'))
        for path in self(paths):
            stream.write(path.get_full_path().encode('utf-8') + b'\0')
        if hasattr(stream, 'write_long'):
            stream.write_long(self.index)
        else:
            stream.write(struct.pack('>Q', self.index))

    def deserialize(self, buffer):
        self._index_type = IndexType.deserialize(buffer.read(1))
        path_num = int.from_bytes(buffer.read(4), 'big')
        self.paths = [PartialPath(read_string(buffer)) for _ in range(path_num)]
        if hasattr(buffer, 'read_long'):
            self.index = buffer.read_long()
        else:
            self.index = struct.unpack('>Q', buffer.read(8))[0]

    def __eq__(self, other):
        return isinstance(other, DropIndexPlan) and \
               (self.paths == other.paths or
                all(path1.get_full_path() == path2.get_full_path() for path1 in self.paths for path2 in other(paths))) and \
               self.index_type == other._index_type

    def __hash__(self):
        return hash((tuple(self.paths), self._index_type))

    def __str__(self):
        return f"paths: {self.paths}, index type: {self._index_type}"
