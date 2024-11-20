class S_UDT32_NEW:
    def __init__(self):
        self.sym_type = None
        self.name = None

    @classmethod
    def create_s_udt32_new(cls, length: int, type: int, reader, ptr) -> 'S_UDT32_NEW':
        s_udt32_new = cls()
        s_udt32_new.init_s_udt32_new(length, type, reader, ptr)
        return s_udt32_new

    def init_s_udt32_new(self, length: int, type: int, reader, ptr):
        self.process_debug_symbol(length, type)

        self.sym_type = reader.read_int(ptr)
        ptr += 4

        name_len = reader.read_byte(ptr)
        ptr += 1

        self.name = reader.read_ascii_string(ptr, name_len).decode('ascii')

    def get_sym_type(self) -> int:
        return self.sym_type
