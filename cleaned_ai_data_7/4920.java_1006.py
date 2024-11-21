class ObjectiveC2_Property:
    def __init__(self, state, reader):
        self._state = state
        name_index = ObjectiveC1_Utilities.read_next_index(reader, state.is_32bit)
        self.name = reader.read_ascii_string(name_index)

        attributes_index = ObjectiveC1_Utilities.read_next_index(reader, state.is_32bit)
        self.attributes = reader.read_ascii_string(attributes_index)

    @property
    def name(self):
        return self.name

    @property
    def attributes(self):
        return self.attributes

    def to_data_type(self) -> dict:
        data_type = {"objc_property": {}}
        data_type["objc_property"]["name"] = {"type": "ASCII", "size": self._state.pointer_size, "description": None}
        data_type["objc_property"]["attributes"] = {"type": "ASCII", "size": self._state.pointer_size, "description": None}

        return data_type

    def apply_to(self):
        pass
