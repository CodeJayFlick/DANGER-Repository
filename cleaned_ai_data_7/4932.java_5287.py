class ObjectiveC1_Method:
    def __init__(self, state, reader, method_type):
        self.name = None
        self.signature = None
        self.address = 0

        super().__init__(state, reader, method_type)

        if state.is_32bit:
            self.name = reader.read_ascii_string()
            self.signature = reader.read_ascii_string()
        else:
            # Assuming the same logic for 64-bit here.
            pass

        self.address = reader.read_int()

    def get_name(self):
        return self.name

    def get_signature(self):
        return self.signature

    def get_address(self):
        return self.address & (2**31 - 1)  # assuming INT_MASK is equivalent to the maximum value for an int in Python.

    def to_data_type(self):
        struct = {"objc_method": {}}
        struct["objc_method"]["category_path"] = ObjectiveC1_Constants.CATEGORY_PATH
        struct["objc_method"]["method_name"] = self.name
        struct["objc_method"]["method_types"] = self.signature
        struct["objc_method"]["method_imp"] = self.address

        return struct


class PointerDataType:
    @staticmethod
    def get_pointer(data_type, size):
        if data_type == "ASCII":
            return {"pointer": f"Pointer to {data_type} ({size})"}
        elif data_type == "VOID":
            return {"pointer": f"Pointer to VOID ({size})"}
        else:
            raise ValueError("Invalid data type")


class StructureDataType:
    def __init__(self, name, size):
        self.name = name
        self.size = size

    def set_category_path(self, category_path):
        self.category_path = category_path

    def add(self, field_type, field_name, default_value=None):
        if isinstance(field_type, dict):
            self[name][field_name] = field_type
        else:
            self[name][field_name] = {"type": field_type, "default": default_value}


class ObjectiveC1_Constants:
    CATEGORY_PATH = ""
