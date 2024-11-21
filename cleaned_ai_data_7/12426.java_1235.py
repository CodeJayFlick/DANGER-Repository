class UnsignedInteger6DataType:
    def __init__(self):
        self.data_type_manager = None

    @staticmethod
    def data_type():
        return UnsignedInteger6DataType()

    def get_description(self):
        return "Unsigned 6-Byte Integer"

    def get_length(self):
        return 6

    def get_opposite_signedness_data_type(self):
        from ghidra.program.model.data import Integer6DataType
        return Integer6DataType().clone(self.get_data_type_manager())

    def clone(self, data_type_manager=None):
        if data_type_manager == self.get_data_type_manager():
            return self
        else:
            return UnsignedInteger6DataType(data_type_manager)
