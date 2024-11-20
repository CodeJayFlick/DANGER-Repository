class S_UDT32:
    def __init__(self):
        self.checksum = None
        self.type_len = None
        self.name = None

    @classmethod
    def create_s_udt32(cls, length: int, type: str, reader, ptr) -> 'S_UDT32':
        s_udt32 = cls()
        s_udt32.init_s_udt32(length, type, reader, ptr)
        return s_udt32

    def init_s_udt32(self, length: int, type: str, reader, ptr):
        self.process_debug_symbol(length, type)

        if type != 'S_UDT32':
            raise ValueError("Incorrect type!")

        self.checksum = reader.read_int(ptr); ptr += 4
        self.type_len = reader.read_byte(ptr); ptr += 1
        self.name = reader.read_ascii_string(ptr, int(self.type_len))
        
    def get_checksum(self):
        return self.checksum

class BinaryReader:
    SIZEOF_INT = 4
    SIZEOF_BYTE = 1
    
    def read_int(self, ptr) -> int:
        # implement your own binary reading logic here
        pass

    def read_byte(self, ptr) -> bytes:
        # implement your own binary reading logic here
        pass

    def read_ascii_string(self, ptr, length):
        # implement your own binary reading logic here
        pass

def process_debug_symbol(length: int, type: str):
    # implement your own debug symbol processing logic here
    pass
