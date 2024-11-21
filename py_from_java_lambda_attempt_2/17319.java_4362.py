Here is the translation of the given Java code into equivalent Python:

```Python
class CreateIndexPlan:
    def __init__(self):
        self.paths = []
        self.props = {}
        self.time = 0
        self.index_type = None
        super().__init__()

    def set_paths(self, paths):
        self(paths)

    def get_paths(self):
        return self.paths

    def serialize(self, stream):
        stream.write_byte(1)  # PhysicalPlanType.CREATE_INDEX.ordinal()
        stream.write(self.index_type.serialize())
        stream.write_long(self.time)
        stream.write_int(len(self.paths))
        for path in self.paths:
            stream.put_string(path.get_full_path())

        if self.props and not self.props.empty():
            stream.write_byte(1)
            ReadWriteIOUtils.write(stream, self.props)
        else:
            stream.write_byte(0)

    def serialize_buffer(self, buffer):
        type = 1  # PhysicalPlanType.CREATE_INDEX.ordinal()
        buffer.put(type)
        buffer.put(self.index_type.serialize())
        buffer.put_long(self.time)
        buffer.put_int(len(self.paths))
        for path in self.paths:
            buffer.put_string(path.get_full_path())

        if self.props and not self.props.empty():
            buffer.put(1)
            ReadWriteIOUtils.write(buffer, self.props)
        else:
            buffer.put(0)

    def deserialize_buffer(self, buffer):
        self.index_type = IndexType.deserialize(buffer.get())
        self.time = buffer.get_long()

        path_num = buffer.get_int()
        self.paths = [PartialPath(read_string(buffer)) for _ in range(path_num)]

        if buffer.get() == 1:
            self.props = ReadWriteIOUtils.read_map(buffer)
        else:
            self.props = {}

    def __eq__(self, other):
        return (isinstance(other, CreateIndexPlan) and
                set(self.paths) == set(other(paths)) and
                self.time == other.time and
                self.index_type == other.index_type)

    def __hash__(self):
        return hash((tuple(self.paths), tuple(self.props.items()), self.time, self.index_type))

    def __str__(self):
        return f"paths: {self.paths}, index type: {self.index_type}, start time: {self.time}, props: {self.props}"
```

Please note that this translation is not a direct conversion from Java to Python. It's more of an equivalent implementation in Python, considering the differences between both languages and their respective libraries.