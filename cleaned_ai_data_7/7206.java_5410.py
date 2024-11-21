class OatQuickMethodHeaderLollipopMR1:
    def __init__(self):
        self.mapping_table_offset = None
        self.vmap_table_offset = None
        self.gc_map_offset = None
        self.frame_info = None
        self.code_size = None

    def read_from_binary_reader(self, reader):
        try:
            self.mapping_table_offset = int.from_bytes(reader.read(4), 'big')
            self.vmap_table_offset = int.from_bytes(reader.read(4), 'big')
            self.gc_map_offset = int.from_bytes(reader.read(4), 'big')
            self.frame_info = QuickMethodFrameInfo()
            self.code_size = int.from_bytes(reader.read(4), 'big')
        except Exception as e:
            print(f"Error reading from binary reader: {e}")

    def get_mapping_table_offset(self):
        return self.mapping_table_offset

    def get_vmap_table_offset(self):
        return self.vmap_table_offset

    def get_gc_map_offset(self):
        return self.gc_map_offset

    def get_frame_info(self):
        return self.frame_info

    def get_code_size(self):
        return self.code_size


class QuickMethodFrameInfo:
    pass  # This class is not implemented in the original code, so I left it as a placeholder.


def to_data_type(self):
    structure = {}
    structure['mapping_table_offset'] = {'type': 'int', 'offset': None}
    structure['vmap_table_offset'] = {'type': 'int', 'offset': None}
    structure['gc_map_offset'] = {'type': 'int', 'offset': None}
    structure['frame_info'] = self.frame_info.to_data_type()
    structure['code_size'] = {'type': 'int', 'offset': None}

    return structure
