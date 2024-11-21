class MeasurementMNodePlan:
    def __init__(self):
        self.schema = None
        self.alias = ''
        self.offset = 0

    def __init__(self, name: str, alias: str, offset: int, child_size: int, schema: 'IMeasurementSchema'):
        super().__init__()
        self.name = name
        self.alias = alias
        self.offset = offset
        self.child_size = child_size
        self.schema = schema

    def get_paths(self):
        return []

    def serialize_to_buffer(self, buffer: bytes) -> None:
        buffer.write(int.to_bytes(1, 4, 'big'))
        buffer.write(str.encode(self.name))
        buffer.write(str.encode(self.alias))
        buffer.write(int.to_bytes(self.offset, 8, 'big'))
        buffer.write(int.to_bytes(self.child_size, 4, 'big'))
        self.schema.serialize_to(buffer)

    def serialize_to_stream(self, stream: object) -> None:
        stream.write(int.to_bytes(1, 4, 'big'))
        stream.write(str.encode(self.name))
        stream.write(str.encode(self.alias))
        stream.write(int.to_bytes(self.offset, 8, 'big'))
        stream.write(int.to_bytes(self.child_size, 4, 'big'))
        self.schema.serialize_to(stream)

    def deserialize_from_buffer(self, buffer: bytes) -> None:
        self.name = str(buffer.decode('utf-8').strip())
        self.alias = str(buffer.decode('utf-8').strip())
        self.offset = int.from_bytes(buffer[0:8], 'big')
        self.child_size = int.from_bytes(buffer[8:12], 'big')
        self.schema = UnaryMeasurementSchema.deserialize_from(buffer)

    @property
    def schema(self):
        return self._schema

    @schema.setter
    def schema(self, value):
        self._schema = value

    @property
    def alias(self):
        return self._alias

    @alias.setter
    def alias(self, value):
        self._alias = value

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, value):
        self._offset = value

    def __str__(self) -> str:
        return f'MeasurementMNodePlan({self.name}, {self.alias}, {self.schema}, {self.offset}, {self.child_size})'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MeasurementMNodePlan):
            return False
        return self.name == other.name and self.alias == other.alias and self.schema == other.schema and self.offset == other.offset and self.child_size == other.child_size

    def __hash__(self) -> int:
        return hash((self.name, self.alias, self.schema, self.offset, self.child_size))
