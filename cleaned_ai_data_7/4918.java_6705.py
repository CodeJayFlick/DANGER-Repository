class ObjectiveC2_Method:
    def __init__(self, state, reader, method_type, is_small):
        self.name = None
        self.types = None
        self.imp = None
        self.is_small = is_small

        super().__init__(state, reader, method_type)

        if is_small:
            name_offset = ObjectiveC1_Utilities.read_next_index(reader)
            name_ptr = reader.read_int(name_offset + 4)
            self.name = reader.read_ascii_string(name_ptr)

            types_offset = ObjectiveC1_Utilities.read_next_index(reader)
            self.types = reader.read_ascii_string(types_offset + 8)

        else:
            name_index = ObjectiveC1_Utilities.read_next_index(reader, state.is_32bit)
            self.name = reader.read_ascii_string(name_index)

            types_index = ObjectiveC1_Utilities.read_next_index(reader, state.is_32bit)
            self.types = reader.read_ascii_string(types_index)

        self.imp = ObjectiveC2_Implementation(state, reader, is_small)

    def get_name(self):
        return self.name

    def get_types(self):
        return self.types

    def get_implementation(self):
        return self.imp.get_implementation()

class DataType:
    pass
