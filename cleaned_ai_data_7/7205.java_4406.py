class OatQuickMethodHeaderLollipop:
    def __init__(self):
        self.mapping_table_offset = None
        self.vmap_table_offset = None
        self.frame_info = None
        self.code_size = None

    def read_from_reader(self, reader):
        try:
            self.mapping_table_offset = reader.read_int()
            self.vmap_table_offset = reader.read_int()
            self.frame_info = QuickMethodFrameInfo(reader)
            self.code_size = reader.read_int()
        except Exception as e:
            print(f"Error reading from reader: {e}")

    def get_mapping_table_offset(self):
        return self.mapping_table_offset

    def get_vmap_table_offset(self):
        return self.vmap_table_offset

    def get_frame_info(self):
        return self.frame_info

    def get_code_size(self):
        return self.code_size


class QuickMethodFrameInfo:
    def __init__(self, reader):
        pass  # Not implemented in this example

    def to_data_type(self):
        pass  # Not implemented in this example
