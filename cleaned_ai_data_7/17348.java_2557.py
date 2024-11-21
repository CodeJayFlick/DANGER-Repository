import io

class ShowDevicesPlan:
    def __init__(self):
        self.show_content_type = "DEVICES"

    has_sg_col = False

    def __init__(self, path):
        super().__init__()
        self.show_content_type = "DEVICES"
        self.path = path

    def __init__(self, path, limit, offset, has_sg_col):
        super().__init__()
        self.show_content_type = "DEVICES"
        self.path = path
        self.limit = limit
        self.offset = offset
        self.has_sg_col = has_sg_col

    def serialize(self, output_stream: io.IO) -> None:
        output_stream.write(1)  # PhysicalPlanType.SHOW_ DEVICES.ordinal()
        output_stream.write_string(self.path.get_full_path())
        output_stream.writeInt(self.limit)
        output_stream.writeInt(self.offset)
        output_stream.writeLong(self.index)

    def deserialize(self, buffer: bytes) -> None:
        self.path = PartialPath(read_string(buffer))
        self.limit = int.from_bytes(buffer.read(4), "big")
        self.offset = int.from_bytes(buffer.read(4), "big")
        self.index = long.from_bytes(buffer.read(8), "big")

    def has_sg_col(self) -> bool:
        return self.has_sg_col
