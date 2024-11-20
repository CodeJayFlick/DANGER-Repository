class ConstantValueAttribute:
    def __init__(self):
        self.constant_value_index = None

    def read_from_binary_reader(self, reader):
        super().__init__()
        self.constant_value_index = reader.read_next_short()

    @property
    def constant_value_index(self):
        return self._constant_value_index & 0xffff

    def to_data_type(self) -> dict:
        structure = {"ConstantValue_attribute": {}}
        structure["ConstantValue_attribute"]["constantvalue_index"] = None
        return structure


class BinaryReader:
    @staticmethod
    def read_next_short():
        # implement your binary reader logic here
        pass

