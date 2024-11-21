class CoffSymbolAuxArray:
    def __init__(self, reader):
        self.tag_index = reader.read_int()
        self.line_number = reader.read_short()
        self.array_size = reader.read_short()
        self.first_dimension = reader.read_short()
        self.second_dimension = reader.read_short()
        self.third_dimension = reader.read_short()
        self.fourth_dimension = reader.read_short()
        self.unused = reader.read_bytes(2)

    def get_tag_index(self):
        return self.tag_index

    def get_line_number(self):
        return self.line_number

    def get_array_size(self):
        return self.array_size

    def get_first_dimension(self):
        return self.first_dimension

    def get_second_dimension(self):
        return self.second_dimension

    def get_third_dimension(self):
        return self.third_dimension

    def get_fourth_dimension(self):
        return self.fourth_dimension

    def get_unused(self):
        return self.unused
