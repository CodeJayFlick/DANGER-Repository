class S_CONSTANT32:
    @classmethod
    def create_s_constant32(cls, length: int, type: int, reader, ptr):
        s_constant32 = cls(reader.get_factory().create(cls))
        s_constant32.init_s_constant32(length, type, reader, ptr)
        return s_constant32

    def __init__(self):
        pass  # DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.

    def init_s_constant32(self, length: int, type: int, reader, ptr) -> None:
        self.process_debug_symbol(length, type)

        unknown1 = reader.read_int(ptr)
        ptr += 4
        unknown2 = reader.read_short(ptr)
        ptr += 2

        name_len = reader.read_byte(ptr)
        ptr += 1

        self.name = reader.read_ascii_string(ptr, Conv.byte_to_int(name_len))

        print(f"S_ CONSTANT32: {unknown1} - {unknown2}")

    def process_debug_symbol(self, length: int, type: int) -> None:
        pass
