class FilledArrayDataPayload:
    MAGIC = 0x0300

    def __init__(self):
        self.ident = None
        self.element_width = None
        self.size = None
        self.data = None

    def from_binary_reader(self, reader):
        try:
            self.ident = reader.read_short()
            self.element_width = reader.read_short()
            self.size = reader.read_int()
            self.data = reader.read_bytes(self.size * self.element_width)
        except Exception as e:
            print(f"Error reading binary data: {e}")

    def get_ident(self):
        return self.ident

    def get_element_width(self):
        return self.element_width

    def get_size(self):
        return self.size

    def get_data(self):
        return self.data
