class MethodIDItem:
    def __init__(self, reader):
        self._file_offset = reader.get_pointer_index()
        self.class_index = reader.read_next_short()
        self.proto_index = reader.read_next_short()
        self.name_index = reader.read_next_int()

    @property
    def file_offset(self):
        return self._file_offset

    @property
    def class_index(self):
        return self.class_index

    @property
    def proto_index(self):
        return self.proto_index

    @property
    def name_index(self):
        return self.name_index


class BinaryReader:
    def get_pointer_index(self):
        pass  # implement this method as needed

    def read_next_short(self):
        pass  # implement this method as needed

    def read_next_int(self):
        pass  # implement this method as needed
