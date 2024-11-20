class ConstantPoolMethodTypeInfo:
    def __init__(self):
        self.descriptor_index = None

    def from_binary_reader(self, reader):
        super().__init__()
        self.descriptor_index = reader.read_next_short()

    @property
    def descriptor_index(self):
        return self.descriptor_index & 0xffff


class DataType:
    pass


def to_data_type(self) -> DataType:
    name = "CONSTANT_MethodType_info"
    structure = {"tag": None, "descriptor_index": None}
    return structure

