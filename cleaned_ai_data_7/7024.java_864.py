class ArtField:
    def __init__(self):
        self.declaring_class = None
        self.access_flags = None
        self.field_dex_idx = None
        self.offset = None

    def from_reader(self, reader):
        try:
            self.declaring_class = int.from_bytes(reader.read(4), 'little')
            self.access_flags = int.from_bytes(reader.read(4), 'little')
            self.field_dex_idx = int.from_bytes(reader.read(4), 'little')
            self.offset = int.from_bytes(reader.read(4), 'little')
        except Exception as e:
            print(f"Error: {e}")

    def get_declaring_class(self):
        return self.declaring_class

    def get_access_flags(self):
        return self.access_flags

    def get_field_dex_index(self):
        return self.field_dex_idx

    def get_offset(self):
        return self.offset
