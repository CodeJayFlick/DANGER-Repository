class BaseRelocation:
    NAME = "IMAGE_BASE_RELOCATION"
    IMAGE_SIZEOF_BASE_RELOCATION = 8
    
    RELATIONSHIP_TYPE_NOOP = 0
    RELATIONSHIP_TYPE_ABSOLUTE = 0
    RELATIONSHIP_TYPE_HIGH = 1
    RELATIONSHIP_TYPE_LOW = 2
    RELATIONSHIP_TYPE_HIGHLOW = 3
    RELATIONSHIP_TYPE_HIGHADJ = 4
    
    RELATIONSHIP_MIPS_JMPADDR = 5
    RELATIONSHIP_SECTION = 6
    RELATIONSHIP_REL32 = 7
    RELATIONSHIP_MIPS_JMPADDR16 = 9
    RELATIONSHIP_IA64_IMM64 = 9
    RELATIONSHIP_DIR64 = 10
    RELATIONSHIP_HIGH3ADJ = 11
    
    TYPE_STRINGS = [
        "ABSOLUTE",
        "HIGH",
        "LOW",
        "HIGHLOW",
        "HIGHADJ",
        "MIPS_JMPADDR",
        "??"*4,
        "IA64_IMM64",
        "DIR64"
    ]

    def __init__(self):
        self.virtual_address = 0
        self.size_of_block = IMAGE_SIZEOF_BASE_RELOCATION
        self.type_offset_list = []

    @classmethod
    def create_base_relocation(cls, reader, index):
        base_relocation = cls()
        base_relocation.init_base_relocation(reader, index)
        return base_relocation

    def init_base_relocation(self, reader, index):
        if not isinstance(reader, int) or not isinstance(index, int):
            raise TypeError("reader and index must be integers")
        
        self.virtual_address = reader
        index += 4
        
        self.size_of_block = reader
        index += 4

        if self.virtual_address < 0:
            return
        
        if self.size_of_block < 0 or self.size_of_block > NTHeader.MAX_SANE_COUNT:
            return
        
        len = (self.size_of_block - IMAGE_SIZEOF_BASE_RELOCATION) // 2
        
        for i in range(len):
            type_offset = reader
            index += 2
            
            self.type_offset_list.append(TypeOffset(type_offset))

    def __init__(self, virtual_address):
        if not isinstance(virtual_address, int):
            raise TypeError("virtual address must be an integer")
        
        self.virtual_address = virtual_address
        self.size_of_block = IMAGE_SIZEOF_BASE_RELOCATION

    def add_relocation(self, type, offset):
        if not isinstance(type, int) or not isinstance(offset, int):
            raise TypeError("type and offset must be integers")

        self.type_offset_list.append(TypeOffset(type, offset))
        self.size_of_block += 2

    @property
    def virtual_address(self):
        return self._virtual_address
    
    @virtual_address.setter
    def virtual_address(self, value):
        if not isinstance(value, int):
            raise TypeError("virtual address must be an integer")
        
        self._virtual_address = value

    @property
    def size_of_block(self):
        return self._size_of_block
    
    @size_of_block.setter
    def size_of_block(self, value):
        if not isinstance(value, int):
            raise TypeError("size of block must be an integer")

        self._size_of_block = value

    @property
    def count(self):
        return len(self.type_offset_list)

    def get_offset(self, index):
        if not isinstance(index, int) or index < 0:
            raise IndexError("index out of range")
        
        return self.type_offset_list[index].offset

    def get_type(self, index):
        if not isinstance(index, int) or index < 0:
            raise IndexError("index out of range")

        return self.type_offset_list[index].type

class TypeOffset:
    def __init__(self, type_offset):
        if not isinstance(type_offset, int):
            raise TypeError("type offset must be an integer")
        
        self.type = (type_offset & 0xF000) >> 12
        self.offset = type_offset & 0x0FFF

    def __init__(self, type, offset):
        if not isinstance(type, int) or not isinstance(offset, int):
            raise TypeError("type and offset must be integers")
        
        self.type = type
        self.offset = offset
        self.type_offset = (self.type << 12) | self.offset

class NTHeader:
    MAX_SANE_COUNT = 0x7FFFFFFF

def to_data_type(self):
    struct = StructureDataType(BaseRelocation.NAME, 0)
    
    struct.add(DWORD("VirtualAddress"), None)
    struct.add(DWORD("SizeOfBlock"), None)
    struct.add(ArrayDataType(WORD, len(self.type_offset_list), WORD.getLength()), "TypeOffset", None)

    return struct

def to_bytes(self):
    bytes = bytearray(self.size_of_block)
    pos = 0
    dc.getBytes(self.virtual_address, bytes, pos)
    pos += 4
    dc.getBytes(self.size_of_block, bytes, pos)
    pos += 4
    
    for i in range(len(self.type_offset_list)):
        type_offset = self.type_offset_list[i].typeOffset
        dc.getBytes(type_offset, bytes, pos)
        pos += 2

    return bytes
