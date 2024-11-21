class SectionHeader:
    NO_NAME_OFFSET = -1

    def __init__(self, reader):
        self._reader = reader
        self.name_offset = reader.read_next_int()
        self.default_address = reader.read_next_int()
        self.total_length = reader.read_next_int()
        self.unpacked_length = reader.read_next_int()
        self.container_length = reader.read_next_int()
        self.container_offset = reader.read_next_int()
        self.section_kind = reader.read_next_byte()
        self.share_kind = reader.read_next_byte()
        self.alignment = reader.read_next_byte()
        self.reserved_a = reader.read_next_byte()

    @property
    def name(self):
        if not hasattr(self, '_name'):
            return str(self.get_section_kind())
        else:
            return self._name

    def get_name_offset(self):
        return self.name_offset

    def get_data(self):
        return self._reader.get_byte_provider().get_input_stream(self.container_offset)

    def unpack_next_value(self, input_stream):
        unpacked = 0
        while True:
            unpacked <<= 7
            value = input_stream.read()
            if (value & 0x80) == 0:
                break
            unpacked += value & 0x7f
        return unpacked

    def get_default_address(self):
        return self.default_address

    def get_total_length(self):
        return self.total_length

    def get_unpacked_length(self):
        return self.unpacked_length

    def get_container_length(self):
        return self.container_length

    def get_container_offset(self):
        return self.container_offset

    @property
    def section_kind(self):
        if not hasattr(self, '_section_kind'):
            self._section_kind = SectionKind.get(self.section_kind)
        return self._section_kind

    @property
    def share_kind(self):
        if not hasattr(self, '_share_kind'):
            self._share_kind = SectionShareKind.get(self.share_kind)
        return self._share_kind

    @property
    def alignment(self):
        return self.alignment

    @property
    def reserved_a(self):
        return self.reserved_a


class SectionKind:
    PackedData, UnpackedData, Code, ExecutableData = range(4)

    @classmethod
    def get(cls, value):
        if value == 0x01:
            return cls.PackedData
        elif value == 0x02:
            return cls.UnpackedData
        elif value == 0x03:
            return cls.Code
        else:
            return cls.ExecutableData


class SectionShareKind:
    ReadWrite, ReadOnly = range(2)

    @classmethod
    def get(cls, value):
        if value == 0x01:
            return cls.ReadWrite
        elif value == 0x02:
            return cls.ReadOnly

