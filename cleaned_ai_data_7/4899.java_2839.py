class Resource:
    FLAG_MOVEABLE = 0x0010
    FLAG_PURE = 0x0020
    FLAG_PRELOAD = 0x0040

    def __init__(self, reader: 'FactoryBundledWithBinaryReader', rt):
        self.reader = reader
        self.rt = rt
        self.file_offset = reader.read_next_short()
        self.file_length = reader.read_next_short()
        self.flagword = reader.read_next_short()
        self.resource_id = reader.read_next_short()
        self.handle = reader.read_next_short()
        self.usage = reader.read_next_short()

    def get_file_offset(self):
        return self.file_offset

    def get_file_length(self):
        return self.file_length

    def get_flagword(self):
        return self.flagword

    def get_resource_id(self):
        return self.resource_id

    def get_handle(self):
        return self.handle

    def get_usage(self):
        return self.usage

    def is_moveable(self):
        return (self.flagword & Resource.FLAG_MOVEABLE) != 0

    def is_pure(self):
        return (self.flagword & Resource.FLAG_PURE) != 0

    def is_preload(self):
        return (self.flagword & Resource.FLAG_PRELOAD) != 0

    def get_file_offset_shifted(self, rt_alignment_shift_count: int):
        shift_int = rt_alignment_shift_count
        offset_int = self.file_offset
        return offset_int << shift_int

    def get_file_length_shifted(self, rt_alignment_shift_count: int):
        shift_int = rt_alignment_shift_count
        length_int = self.file_length
        return length_int << shift_int

    def get_bytes(self) -> bytes:
        try:
            return self.reader.read_byte_array(self.get_file_offset_shifted(), self.get_file_length_shifted())
        except Exception as e:
            print(f"Error: {e}")
            return None

    def __str__(self):
        if (self.resource_id & 0x8000) != 0:
            return f"{(self.resource_id & 0x7fff)}"
        else:
            names = self.rt.get_resource_names()
            for name in names:
                if self.resource_id == name.index - self.rt.index:
                    return name.name
            if self.resource_id >= 0 and self.resource_id < len(names):
                return names[self.resource_id].name
        return f"NE - Resource - unknown id - {hex(self.resource_id)}"
