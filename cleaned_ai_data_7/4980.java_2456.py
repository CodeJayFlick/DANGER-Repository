class CliSigConstant:
    def __init__(self, blob, element_type):
        self.type = element_type
        super().__init__(blob)

    @property
    def value(self):
        if not hasattr(self, '_value'):
            reader = self.blob.get_contents_reader()
            switcher = {
                'ELEMENT_ETYPE_BOOLEAN': lambda: reader.read_next_byte(),
                'ELEMENT_TYPE_CHAR': lambda: reader.read_next_byte(),
                'ELEMENT_TYPE_U2': lambda: reader.read_next_unsigned_short(),
                'ELEMENT_TYPE_I2': lambda: reader.read_next_short(),
                'ELEMENT_TYPE_U4': lambda: reader.read_next_unsigned_int(),
                'ELEMENT_TYPE_I4': lambda: reader.read_next_int(),
                'ELEMENT_TYPE_R4': lambda: float.from_bytes(reader.read_next_bytearray(4), byteorder='little'),
                'ELEMENT_TYPE_U8': lambda: int.from_bytes(reader.read_next_bytearray(8), byteorder='little'),
                'ELEMENT_TYPE_I8': lambda: reader.read_next_long(),
                'ELEMENT_TYPE_R8': lambda: float.from_bytes(reader.read_next_bytearray(8), byteorder='little'),
                'ELEMENT_TYPE_STRING': lambda: self.blob.get_contents_reader().read_next_bytearray(self.contents_size).decode('utf-16le')
            }
            value = switcher.get(str(self.type))()
            setattr(self, '_value', value)
        return getattr(self, '_value')

    def get_contents_data_type(self):
        struct = StructureDataType(CategoryPath(PATH), self.name(), 0)

        if hasattr(self, 'type'):
            switcher = {
                'ELEMENT_TYPE_BOOLEAN': lambda: (BYTE, self.type.name(), ''),
                'ELEMENT_TYPE_CHAR': lambda: (BYTE, self.type.name(), ''),
                'ELEMENT_TYPE_U2': lambda: (WORD, self.type.name(), ''),
                'ELEMENT_TYPE_I2': lambda: (WORD, self.type.name(), '') if int(self.value) >= 0 else (WORD, self.type.name(), get_representation()),
                'ELEMENT_TYPE_U4': lambda: (DWORD, self.type.name(), ''),
                'ELEMENT_TYPE_I4': lambda: (DWORD, self.type.name(), '') if int(self.value) >= 0 else (DWORD, self.type.name(), get_representation()),
                'ELEMENT_TYPE_R4': lambda: (DWORD, self.type.name(), get_representation),
                'ELEMENT_TYPE_U8': lambda: (QWORD, self.type.name(), ''),
                'ELEMENT_TYPE_I8': lambda: (QWORD, self.type.name(), '') if int(self.value) >= 0 else (QWORD, self.type.name(), get_representation()),
                'ELEMENT_TYPE_R8': lambda: (QWORD, self.type.name(), get_representation),
                'ELEMENT_TYPE_STRING': lambda: (UTF16, self.contents_size, self.type.name(), '')
            }
            struct.add(*switcher.get(str(self.type))())
        return struct

    def get_contents_name(self):
        return "ConstantSig"

    def get_contents_comment(self):
        return "Data stored in a constant"

    @property
    def contents_size(self):
        if not hasattr(self, '_contents_size'):
            self._contents_size = len(self.blob.get_contents())
        return getattr(self, '_contents_size')

    def get_representation_common(self, stream, is_short=False):
        return str(self.value)
