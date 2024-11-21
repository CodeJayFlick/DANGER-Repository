import io


class OatMethodOffsets:
    def __init__(self, reader):
        self.code_offset = reader.read_int()

    @property
    def code_offset(self):
        return self._code_offset

    def to_data_type(self) -> dict:
        data_type = {"category_path": "/oat"}
        return data_type


class BinaryReader(io.BufferedReader):
    def read_next_int(self) -> int:
        # implement your logic here, this is just a placeholder
        pass
