import io


class InnerClass:
    def __init__(self):
        self.inner_class_info_index = 0
        self.outer_class_info_index = 0
        self.inner_name_index = 0
        self.inner_class_access_flags = 0

    def from_binary_reader(self, reader: 'io.BinaryReader') -> None:
        if not isinstance(reader, io.BinaryReader):
            raise TypeError("reader must be an instance of BinaryReader")
        self.inner_class_info_index = reader.read_next_short()
        self.outer_class_info_index = reader.read_next_short()
        self.inner_name_index = reader.read_next_short()
        self.inner_class_access_flags = reader.read_next_short()

    def get_inner_class_info_index(self) -> int:
        return self.inner_class_info_index & 0xffff

    def get_outer_class_info_index(self) -> int:
        return self.outer_class_info_index & 0xffff

    def get_inner_name_index(self) -> int:
        return self.inner_name_index & 0xffff

    def get_inner_class_access_flags(self) -> int:
        return self.inner_class_access_flags


class BinaryReader:
    pass
