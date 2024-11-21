class ConstantPoolNameAndTypeInfo:
    def __init__(self):
        self.name_index = None
        self.descriptor_index = None

    def read_from_binary_reader(self, reader):
        try:
            super().__init__()
            self.name_index = reader.read_next_short()
            self.descriptor_index = reader.read_next_short()
        except Exception as e:
            print(f"Error reading from binary reader: {e}")

    @property
    def name_index(self):
        return self.name_index & 0xffff

    @property
    def descriptor_index(self):
        return self.descriptor_index & 0xffff

    def to_data_type(self) -> dict:
        data_type = {
            "name": "CONSTANT_ NameAndType_info",
            "structure": [
                {"type": "byte", "field_name": "tag"},
                {"type": "word", "field_name": "name_index"},
                {"type": "word", "field_name": "descriptor_index"}
            ]
        }
        return data_type
