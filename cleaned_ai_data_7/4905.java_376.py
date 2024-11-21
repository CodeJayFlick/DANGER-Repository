class SegmentRelocation:
    VALUES_SIZE = 5
    
    MOVEABLE = 0xff
    TYPE_MASK = 0x0f
    TYPE_LO_BYTE = 0x00
    TYPE_SEGMENT = 0x02
    TYPE_FAR_ADDR = 0x03
    TYPE_OFFSET = 0x05
    TYPE_FAR_ADDR_48 = 0x0c
    TYPE_OFFSET_32 = 0x0d
    
    TYPE_STRINGS = [
        "Low Byte",
        "???1",
        "16-bit Segment Selector",
        "32-bit Pointer",
        "???4",
        "16- bit Pointer",
        "???6",
        "???7",
        "???8",
        "???9",
        "???10",
        "48- bit Pointer",
        "???12",
        "32- bit Offset"
    ]
    
    TYPE_LENGTHS = [
        1,  # TYPE_LO_BYTE
        0,
        2,  # TYPE_SEGMENT
        4,  # TYPE_FAR_ADDR
        0,
        2,  # TYPE_OFFSET
        0,
        0,
        0,
        0,
        0,
        6,  # TYPE_FAR_ADDR_48
        4   # TYPE_OFFSET_32
    ]
    
    FLAG_TARGET_MASK = 0x03
    FLAG_INTERNAL_REF = 0x00
    FLAG_IMPORT_ORDINAL = 0x01
    FLAG_IMPORT_NAME = 0x02
    FLAG_OS_FIXUP = 0x03
    FLAG_ADDITIVE = 0x04

    def __init__(self, segment):
        self.segment = segment
        self.type = None
        self.flagbyte = None
        self.offset = None
        self.target_segment = None
        self.target_offset = None
    
    @classmethod
    def from_reader(cls, reader, segment):
        relocation = cls(segment)
        relocation.type = reader.read_next_byte()
        relocation.flagbyte = reader.read_next_byte()
        relocation.offset = reader.read_next_short()
        relocation.target_segment = reader.read_next_short()
        relocation.target_offset = reader.read_next_short()
        return relocation
    
    @classmethod
    def from_values(cls, type, values):
        if len(values) != cls.VALUES_SIZE:
            raise ValueError("Expected " + str(cls.VALUES_SIZE) + " values")
        
        relocation = cls(0)
        relocation.type = type
        relocation.segment = int(values[0])
        relocation.flagbyte = bytes([values[1]])
        relocation.offset = int.from_bytes(values[2].to_bytes((values[2].bit_length() + 7) // 8, 'big'), byteorder='big')
        relocation.target_segment = int.from_bytes(values[3].to_bytes((values[3].bit_length() + 7) // 8, 'big'), byteorder='big')
        relocation.target_offset = int.from_bytes(values[4].to_bytes((values[4].bit_length() + 7) // 8, 'big'), byteorder='big')
        
        return relocation
    
    def is_internal_ref(self):
        return (self.flagbyte & self.FLAG_TARGET_MASK) == self.FLAG_INTERNAL_REF
    
    def is_import_ordinal(self):
        return (self.flagbyte & self.FLAG_TARGET_MASK) == self.FLAG_IMPORT_ORDINAL
    
    def is_import_name(self):
        return (self.flagbyte & self.FLAG_TARGET_MASK) == self.FLAG_IMPORT_NAME
    
    def is_op_sys_fixup(self):
        return (self.flagbyte & self.FLAG_TARGET_MASK) == self.FLAG_OS_FIXUP
    
    def is_additive(self):
        return bool((self.flagbyte & self.FLAG_ADDITIVE))
    
    @property
    def type_(self):
        return self.type
    
    @property
    def flag_byte(self):
        return self.flagbyte
    
    @property
    def offset_(self):
        return self.offset
    
    @property
    def target_segment_(self):
        return self.target_segment
    
    @property
    def target_offset_(self):
        return self.target_offset
    
    def get_values(self):
        return [int(self.segment), int.from_bytes(self.flagbyte, byteorder='big'), int(self.offset_), int(self.target_segment_), int(self.target_offset_)]
