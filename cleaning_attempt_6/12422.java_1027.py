class UnsignedCharDataType:
    def __init__(self):
        self.data_type_manager = None

    @property
    def data_type_manager(self):
        return self._data_type_manager

    @data_type_manager.setter
    def data_type_manager(self, value):
        self._data_type_manager = value

    def get_description(self):
        return "Unsigned Character (ASCII)"

    def clone(self, dtm=None):
        if dtm == self.data_type_manager:
            return self
        else:
            new_instance = UnsignedCharDataType()
            new_instance.data_type_manager = dtm
            return new_instance

    def default_label_prefix(self):
        return "UCHAR"

    def get_c_declaration(self):
        return "unsigned char"

    def get_c_type_declaration(self, data_organization=None):
        if data_organization is None:
            return self.get_c_declaration()
        else:
            # standard C-primitive type with modified name
            return f"{self.name} {self.get_c_declaration()}".replace("uchar", "")

# Create an instance of the UnsignedCharDataType class
data_type = UnsignedCharDataType()

print(data_type.get_description())  # Output: "Unsigned Character (ASCII)"
