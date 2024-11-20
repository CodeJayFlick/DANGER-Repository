class PdbDebugInfo:
    def __init__(self):
        self.pdb = None
        self.stream_number = 0
        self.version_number = 0
        self.stream_number_global_static_symbols_hash_maybe = 0
        self.stream_number_public_static_symbols_hash_maybe = 0
        self.stream_number_symbol_records = 0

    def deserialize(self, header_only=False):
        if not header_only:
            reader = self.pdb.get_reader_for_stream_number(self.stream_number)
            self.deserialize_header(reader)

    @staticmethod
    def get_version_number_size():
        return 4

    def process_module_information(self, reader, monitor, skip):
        pass

    def dump_file_info(self, writer):
        if not hasattr(self, 'file_length'):
            return
        file_reader = self.pdb.get_sub_pdb_byte_reader(self.file_length)
        num_modules = file_reader.parse_unsigned_short_val()
        for _ in range(num_modules):
            monitor.check_cancelled()
            module_name_offset = file_reader.parse_unsigned_int_val()
            writer.write(f"Module Name Offset: {module_name_offset}\n")

    def parse_file_info_name(self, reader):
        pass

class AbstractPdb:
    @staticmethod
    def get_reader_for_stream_number(stream_number):
        # TO DO: implement this method
        return None

class PdbByteReader:
    def __init__(self, data):
        self.data = data
        self.index = 0

    def parse_unsigned_short_val(self):
        val = int.from_bytes(self.data[self.index:self.index+2], 'little')
        self.index += 2
        return val

    def parse_unsigned_int_val(self):
        val = int.from_bytes(self.data[self.index:self.index+4], 'little')
        self.index += 4
        return val

class SegmentMapDescription:
    pass

def main():
    pdb_debug_info = PdbDebugInfo()
    # TO DO: implement the rest of this method
