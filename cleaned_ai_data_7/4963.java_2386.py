class OmfRecord:
    def read_record_header(self):
        pass  # implement this method in your subclass

    @staticmethod
    def read_index(reader):
        return reader.read_int()

    @staticmethod
    def read_string(reader):
        length = reader.read_int()
        return reader.read(length)

    @staticmethod
    def read_int2_or_4(reader, has_big_fields):
        if has_big_fields:
            return reader.read_long()
        else:
            return reader.read_int()

class OmfSymbolRecord(OmfRecord):
    def __init__(self, is_static=False):
        self.is_static = is_static

    def read_record_header(self, reader):
        super().read_record_header()  # implement this method in your subclass
        max = reader.tell + len(self) - 1
        has_big_fields = self.has_big_fields()
        self.base_group_index = OmfRecord.read_index(reader)
        self.base_segment_index = OmfRecord.read_index(reader)

    def get_base_frame(self):
        if self.base_segment_index == 0:
            return reader.read_short() & 0xffff

class OmfSymbolRecord(OmfRecord):
    def __init__(self, is_static=False):
        super().__init__()
        self.is_static = is_static
        self.symbol_list = []

    def read_record_header(self, reader):
        max = reader.tell + len(self) - 1
        has_big_fields = self.has_big_fields()
        while reader.tell < max:
            name = OmfRecord.read_string(reader)
            offset = (OmfRecord.read_int2_or_4(reader, has_big_fields) & 0xffffffff).to_bytes(4, 'little')
            type = OmfRecord.read_index(reader)
            subrec = OmfSymbol(name, type, offset, 0, 0)
            self.symbol_list.append(subrec)

    def read_check_sum_byte(self, reader):
        pass  # implement this method in your subclass

class OmfSymbol:
    def __init__(self, name, type, offset, size, flags):
        self.name = name
        self.type = type
        self.offset = offset
        self.size = size
        self.flags = flags

# usage example:

reader = BinaryReader()  # implement this class in your subclass
omf_symbol_record = OmfSymbolRecord(reader, is_static=True)
print(omf_symbol_record.is_static())
print(omf_symbol_record.get_group_index())
print(omf_symbol_record.get_segment_index())
print(len(omf_symbol_record.symbol))
for i in range(len(omf_symbol_record.symbol)):
    print(omf_symbol_record.symbol[i])
